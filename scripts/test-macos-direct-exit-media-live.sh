#!/usr/bin/env bash
# Opt-in installed-client smoke for the failure mode where ordinary pages load
# but YouTube media or DNS fails after DIRECT/EXIT switching.
set -euo pipefail

if [[ ${RATELMESH_LIVE_NETWORK_SMOKE:-} != 1 ]]; then
    echo "refusing live route changes: set RATELMESH_LIVE_NETWORK_SMOKE=1" >&2
    exit 2
fi
if [[ -z ${RATELMESH_TEST_EXIT:-} ]]; then
    echo "set RATELMESH_TEST_EXIT to an online EXIT peer name" >&2
    exit 2
fi

readonly LOCAL_API=${RATELMESH_LOCAL_API:-http://127.0.0.1:8088}
readonly TEST_EXIT=$RATELMESH_TEST_EXIT
readonly CYCLES=${RATELMESH_TEST_CYCLES:-2}
readonly WAIT_SECONDS=${RATELMESH_TEST_WAIT_SECONDS:-60}
readonly RESTORE_WAIT_SECONDS=60
readonly YOUTUBE_URL=https://www.youtube.com/generate_204
readonly GOOGLEVIDEO_URL=https://redirector.googlevideo.com/report_mapping
readonly MIN_MEDIA_BYTES=32768
readonly MAX_MEDIA_BYTES=8388608

case "$LOCAL_API" in
    http://127.0.0.1:* | http://localhost:* | http://\[::1\]:*) ;;
    *)
        echo "RATELMESH_LOCAL_API must use an HTTP loopback address" >&2
        exit 2
        ;;
esac
if ! [[ $CYCLES =~ ^[1-9][0-9]*$ ]] || ((CYCLES > 10)); then
    echo "RATELMESH_TEST_CYCLES must be between 1 and 10" >&2
    exit 2
fi
if ! [[ $WAIT_SECONDS =~ ^[1-9][0-9]*$ ]] || ((WAIT_SECONDS > 300)); then
    echo "RATELMESH_TEST_WAIT_SECONDS must be between 1 and 300" >&2
    exit 2
fi
for command_name in curl jq dscacheutil; do
    command -v "$command_name" >/dev/null || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

umask 077
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-media-smoke.XXXXXX")
STATUS_FILE=$WORK/status.json
restored=0
route_mutated=0
initial_selected=
initial_active=

fetch_status() {
    curl --fail --silent --show-error \
        --noproxy '*' \
        --connect-timeout 2 --max-time 5 \
        --output "$STATUS_FILE" \
        "$LOCAL_API/localapi/status"
    jq -e '.state == "Running"' "$STATUS_FILE" >/dev/null
}

post_clear() {
    curl --fail --silent --show-error \
        --noproxy '*' \
        --connect-timeout 2 --max-time 10 \
        --request POST --output /dev/null \
        "$LOCAL_API/localapi/exit/clear"
}

post_exit() {
    local name=$1
    # The local API deliberately reads the name from the query string.
    curl --fail --silent --show-error \
        --noproxy '*' \
        --connect-timeout 2 --max-time 10 \
        --request POST --get --data-urlencode "name=$name" \
        --output /dev/null \
        "$LOCAL_API/localapi/exit/use"
}

wait_direct() {
    local timeout=${1:-$WAIT_SECONDS}
    local deadline=$((SECONDS + timeout))
    while ((SECONDS < deadline)); do
        if fetch_status &&
            jq -e '
                (.selectedExit // "") == "" and
                (.activeExit // "") == "" and
                (.dns // "system") == "system"
            ' "$STATUS_FILE" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_exit() {
    local name=$1
    local deadline=$((SECONDS + WAIT_SECONDS))
    while ((SECONDS < deadline)); do
        if fetch_status &&
            jq -e --arg name "$name" '
                (.selectedExit // "") == $name and
                (.activeExit // "") == $name and
                .exitTrafficVerified == true and
                .killSwitch == true and
                .internetFallback == false and
                (.dns // "system") != "system"
            ' "$STATUS_FILE" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_selected_exit() {
    local name=$1
    local require_active=$2
    local timeout=${3:-$WAIT_SECONDS}
    local deadline=$((SECONDS + timeout))
    while ((SECONDS < deadline)); do
        if fetch_status &&
            jq -e --arg name "$name" --argjson require_active "$require_active" '
                (.selectedExit // "") == $name and
                ($require_active == false or (.activeExit // "") == $name)
            ' "$STATUS_FILE" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

restore_initial_route() {
    if [[ -n $initial_selected ]]; then
        post_exit "$initial_selected" || return 1
        if [[ -n $initial_active ]]; then
            wait_selected_exit "$initial_selected" true "$RESTORE_WAIT_SECONDS" || return 1
        else
            wait_selected_exit "$initial_selected" false "$RESTORE_WAIT_SECONDS" || return 1
        fi
    else
        post_clear || return 1
        wait_direct "$RESTORE_WAIT_SECONDS" || return 1
    fi
    restored=1
}

cleanup() {
    local code=$?
    trap '' INT TERM
    trap - EXIT
    if ((route_mutated == 1 && restored == 0)); then
        if ! restore_initial_route; then
            echo "WARNING: could not restore initial route; use the RatelMesh menu immediately" >&2
            if ((code == 0)); then
                code=1
            fi
        fi
    fi
    rm -rf "$WORK"
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

check_media() {
    local phase=$1
    local body=$WORK/googlevideo.body
    local code
    local content_type
    local response
    local size

    # dscacheutil exercises the same app-facing resolver path as curl. During
    # EXIT, wait_exit has already required a non-system upstream and fail-closed
    # tunnel policy, so a successful request cannot escape over DIRECT.
    if ! dscacheutil -q host -a name www.youtube.com |
        grep -Eq '^(ip_address|ipv4_address|ipv6_address):[[:space:]]+'; then
        echo "$phase: system DNS did not resolve www.youtube.com" >&2
        return 1
    fi
    if ! dscacheutil -q host -a name redirector.googlevideo.com |
        grep -Eq '^(ip_address|ipv4_address|ipv6_address):[[:space:]]+'; then
        echo "$phase: system DNS did not resolve redirector.googlevideo.com" >&2
        return 1
    fi

    code=$(
        curl --silent --show-error --location \
            --noproxy '*' --max-redirs 3 \
            --proto '=https' --tlsv1.2 \
            --connect-timeout 5 --max-time 20 \
            --output /dev/null --write-out '%{http_code}' \
            "$YOUTUBE_URL"
    ) || return 1
    if [[ $code != 204 ]]; then
        echo "$phase: YouTube connectivity returned HTTP $code, want 204" >&2
        return 1
    fi

    response=$(
        curl --silent --show-error --location \
            --noproxy '*' --max-redirs 3 \
            --proto '=https' --tlsv1.2 \
            --connect-timeout 5 --max-time 30 \
            --max-filesize "$MAX_MEDIA_BYTES" \
            --output "$body" --write-out '%{http_code}|%{content_type}' \
            "$GOOGLEVIDEO_URL"
    ) || return 1
    code=${response%%|*}
    content_type=${response#*|}
    if [[ $code != 200 ]]; then
        echo "$phase: Google Video connectivity returned HTTP $code, want 200" >&2
        return 1
    fi
    if [[ $content_type != text/plain* ]]; then
        echo "$phase: Google Video returned an unexpected content type" >&2
        return 1
    fi
    size=$(wc -c <"$body" | tr -d ' ')
    if ((size < MIN_MEDIA_BYTES)); then
        echo "$phase: Google Video transferred $size bytes, want at least $MIN_MEDIA_BYTES" >&2
        return 1
    fi
    if ! head -n 1 "$body" |
        grep -Eq '^[0-9A-Fa-f:.]+[[:space:]]+=>[[:space:]]+[[:alnum:]._-]+'; then
        echo "$phase: Google Video mapping body had an unexpected shape" >&2
        return 1
    fi
    rm -f "$body"
    echo "$phase: DNS, YouTube, and Google Video passed ($size bytes)"
}

if ! fetch_status; then
    echo "installed RatelMesh daemon is unavailable or not Running" >&2
    exit 2
fi
initial_selected=$(
    jq -r '
        if (.selectedExit // "") != "" then .selectedExit
        else (.activeExit // "")
        end
    ' "$STATUS_FILE"
)
initial_active=$(jq -r '.activeExit // ""' "$STATUS_FILE")

if ! jq -e --arg name "$TEST_EXIT" '
    .peers[]? |
    select(.role == "exit" and .online == true and .name == $name)
' "$STATUS_FILE" >/dev/null; then
    echo "test EXIT '$TEST_EXIT' is absent, offline, or not an EXIT peer" >&2
    exit 2
fi
if [[ -n $initial_selected ]] &&
    ! jq -e --arg name "$initial_selected" '
        .peers[]? |
        select(.role == "exit" and .online == true and .name == $name)
    ' "$STATUS_FILE" >/dev/null; then
    echo "initial EXIT '$initial_selected' is offline; refusing a route change that cannot be restored" >&2
    exit 2
fi
if ! jq -e '.internetFallback == false' "$STATUS_FILE" >/dev/null; then
    echo "disable internet fallback before running the EXIT media smoke" >&2
    exit 2
fi

echo "DIRECT preflight"
route_mutated=1
post_clear
if ! wait_direct; then
    echo "DIRECT did not become ready within ${WAIT_SECONDS}s" >&2
    exit 1
fi
if ! check_media "DIRECT preflight"; then
    echo "external media baseline is unavailable; treating this run as infrastructure skip" >&2
    exit 77
fi

for ((cycle = 1; cycle <= CYCLES; cycle++)); do
    echo "cycle $cycle/$CYCLES: EXIT $TEST_EXIT"
    post_exit "$TEST_EXIT"
    if ! wait_exit "$TEST_EXIT"; then
        echo "EXIT did not become traffic/DNS verified within ${WAIT_SECONDS}s" >&2
        exit 1
    fi
    check_media "cycle $cycle EXIT"

    echo "cycle $cycle/$CYCLES: DIRECT"
    post_clear
    if ! wait_direct; then
        echo "DIRECT did not recover within ${WAIT_SECONDS}s" >&2
        exit 1
    fi
    check_media "cycle $cycle DIRECT"
done

restore_initial_route
echo "PASS: $CYCLES DIRECT/EXIT media cycles completed and the initial route was restored"
