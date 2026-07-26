#!/usr/bin/env bash
# Build, Developer ID sign, notarize, staple, and sign the update feed for a
# production macOS release. This script intentionally has no unsigned mode.
set -euo pipefail

release_identity_fail() {
  echo "macOS release identity verification failed: $*" >&2
  exit 1
}

release_identity_team() {
  local identity=$1
  local kind=$2
  local prefix
  case "$kind" in
    application) prefix="Developer ID Application:" ;;
    installer) prefix="Developer ID Installer:" ;;
    *) release_identity_fail "unknown identity kind: $kind" ;;
  esac
  if [[ "$identity" == *$'\n'* ||
        ! "$identity" =~ ^${prefix}[[:space:]].+[[:space:]]\(([A-Z0-9]{10})\)$ ]]; then
    release_identity_fail "identity is not an exact $prefix identity"
  fi
  printf '%s\n' "${BASH_REMATCH[1]}"
}

release_identity_require_team() {
  local actual=$1
  local expected=$2
  local subject=$3
  [[ "$expected" =~ ^[A-Z0-9]{10}$ ]] ||
    release_identity_fail "RATELMESH_APPLE_TEAM_ID must contain exactly 10 uppercase letters or digits"
  [[ "$actual" == "$expected" ]] ||
    release_identity_fail "$subject belongs to Apple Team $actual, expected $expected"
}

release_identity_check() {
  local mode=${1:-}
  shift || true
  case "$mode" in
    requested)
      [[ $# -eq 3 ]] ||
        release_identity_fail "requested mode needs application identity, installer identity, and team ID"
      local application_identity=$1 installer_identity=$2 expected_team=$3
      local identities installer_certificate installer_subject
      release_identity_require_team \
        "$(release_identity_team "$application_identity" application)" \
        "$expected_team" "Application identity"
      release_identity_require_team \
        "$(release_identity_team "$installer_identity" installer)" \
        "$expected_team" "Installer identity"
      identities=$(security find-identity -v -p codesigning) ||
        release_identity_fail "could not read code-signing identities"
      grep -Fq "\"$application_identity\"" <<<"$identities" ||
        release_identity_fail "Application identity is unavailable: $application_identity"
      installer_certificate=$(security find-certificate -c "$installer_identity" -p) ||
        release_identity_fail "Installer certificate is unavailable: $installer_identity"
      installer_subject=$(openssl x509 -noout -subject -nameopt RFC2253 <<<"$installer_certificate") ||
        release_identity_fail "could not inspect Installer certificate subject"
      [[ "$installer_subject" == *"CN=$installer_identity,"* ]] ||
        release_identity_fail "Installer certificate CN does not exactly match $installer_identity"
      [[ "$installer_subject" == *",OU=$expected_team,"* ]] ||
        release_identity_fail "Installer certificate OU does not exactly match $expected_team"
      ;;
    app)
      [[ $# -eq 3 ]] ||
        release_identity_fail "app mode needs app path, application identity, and team ID"
      local app_path=$1 application_identity=$2 expected_team=$3 signature
      release_identity_require_team \
        "$(release_identity_team "$application_identity" application)" \
        "$expected_team" "Application identity"
      signature=$(codesign -d --verbose=4 "$app_path" 2>&1) ||
        release_identity_fail "could not inspect signed app: $app_path"
      [[ $(grep -Fxc "Authority=$application_identity" <<<"$signature") -eq 1 ]] ||
        release_identity_fail "signed app authority does not exactly match $application_identity"
      [[ $(grep -Fxc "TeamIdentifier=$expected_team" <<<"$signature") -eq 1 ]] ||
        release_identity_fail "signed app TeamIdentifier does not exactly match $expected_team"
      ;;
    package)
      [[ $# -eq 3 ]] ||
        release_identity_fail "package mode needs package path, installer identity, and team ID"
      local package_path=$1 installer_identity=$2 expected_team=$3 signature leaf
      release_identity_require_team \
        "$(release_identity_team "$installer_identity" installer)" \
        "$expected_team" "Installer identity"
      signature=$(pkgutil --check-signature "$package_path" 2>&1) ||
        release_identity_fail "could not verify signed package: $package_path"
      leaf=$(sed -nE 's/^[[:space:]]*1\. (.*)$/\1/p' <<<"$signature")
      [[ "$leaf" == "$installer_identity" ]] ||
        release_identity_fail "package leaf certificate does not exactly match $installer_identity"
      release_identity_require_team \
        "$(release_identity_team "$leaf" installer)" \
        "$expected_team" "Package leaf certificate OU"
      ;;
    *) release_identity_fail "unknown verification mode: $mode" ;;
  esac
}

release_notary_check() {
  [[ $# -eq 1 ]] ||
    release_identity_fail "notary-check mode needs one result file"
  local result=$1 status
  [[ -f "$result" && ! -L "$result" ]] ||
    release_identity_fail "notary result is not a regular file"
  status=$(plutil -extract status raw -o - "$result" 2>/dev/null) ||
    release_identity_fail "notary result has no readable status"
  [[ "$status" == "Accepted" ]] ||
    release_identity_fail "Apple notarization status is $status, expected Accepted"
}

if [[ "${1:-}" == "identity-check" ]]; then
  shift
  release_identity_check "$@"
  exit 0
fi
if [[ "${1:-}" == "notary-check" ]]; then
  shift
  release_notary_check "$@"
  exit 0
fi

if [[ $# -ne 2 ]]; then
  echo "usage: $0 VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi
if [[ ! "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "version must use canonical MAJOR.MINOR.PATCH without leading zeros" >&2
  exit 2
fi

VERSION=$1
OUTDIR=$2
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_COMMIT="$(git -C "$REPO" rev-parse --verify HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$REPO" show -s --format=%ct HEAD)"
if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ||
      ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "source commit metadata is invalid" >&2
  exit 2
fi
if [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=all)" ]]; then
  echo "source tree must be clean before building release artifacts" >&2
  exit 2
fi
# shellcheck disable=SC1091
source "$REPO/packaging/macos/dependencies.env"
RELEASE_KEY="${RATELMESH_RELEASE_KEY:-$HOME/.config/ratelmesh/release-ed25519.key}"
APPLICATION_IDENTITY="${RATELMESH_APPLICATION_IDENTITY:-}"
INSTALLER_IDENTITY="${RATELMESH_INSTALLER_IDENTITY:-}"
NOTARY_PROFILE="${RATELMESH_NOTARY_PROFILE:-}"
NOTARY_KEYCHAIN="${RATELMESH_NOTARY_KEYCHAIN:-}"
APPLE_TEAM_ID="${RATELMESH_APPLE_TEAM_ID:-}"
PACKAGE_NAME="RatelMesh-macOS-$VERSION-universal.pkg"
PACKAGE_URL="https://download.ratelmesh.com/download/$PACKAGE_NAME"

for required in "$RELEASE_KEY" "$RELEASE_KEY.mldsa65"; do
  if [[ ! -f "$required" ]]; then
    echo "required file is missing: $required" >&2
    exit 2
  fi
done
if [[ "$(GOTOOLCHAIN=local go version | awk '{print $3}')" != "$RATELMESH_GO_VERSION" ]]; then
  echo "Go $RATELMESH_GO_VERSION is required for this release" >&2
  exit 2
fi
if [[ -z "$APPLICATION_IDENTITY" || -z "$INSTALLER_IDENTITY" ||
      -z "$NOTARY_PROFILE" || -z "$APPLE_TEAM_ID" ]]; then
  echo "RATELMESH_APPLICATION_IDENTITY, RATELMESH_INSTALLER_IDENTITY, RATELMESH_NOTARY_PROFILE, and RATELMESH_APPLE_TEAM_ID are required" >&2
  exit 2
fi
"$REPO/scripts/release-macos.sh" identity-check requested \
  "$APPLICATION_IDENTITY" "$INSTALLER_IDENTITY" "$APPLE_TEAM_ID"

if [[ -e "$OUTDIR" ]]; then
  echo "output directory must not already exist: $OUTDIR" >&2
  exit 2
fi
if [[ -L "$OUTDIR" ]]; then
  echo "output directory must not be a symbolic link: $OUTDIR" >&2
  exit 2
fi
OUT_PARENT="$(dirname -- "$OUTDIR")"
mkdir -p "$OUT_PARENT"
OUT_PARENT="$(cd "$OUT_PARENT" && pwd)"
OUTDIR="$OUT_PARENT/$(basename -- "$OUTDIR")"
STAGE="$(mktemp -d "$OUT_PARENT/.ratelmesh-release.XXXXXX")"
chmod 0700 "$STAGE"
EXPANDED=
cleanup_release() {
  if [[ -n "$EXPANDED" ]]; then
    rm -rf "$EXPANDED"
  fi
  if [[ -n "$STAGE" ]]; then
    rm -rf "$STAGE"
  fi
}
trap cleanup_release EXIT HUP INT TERM
PUBLIC_KEY=$(go run "$REPO/scripts/update-manifest.go" public -key "$RELEASE_KEY")
PQ_PUBLIC_KEY=$(go run "$REPO/scripts/update-manifest.go" public-pq -key "$RELEASE_KEY")

RATELMESH_UPDATE_PUBLIC_KEY="$PUBLIC_KEY" \
RATELMESH_UPDATE_PQ_PUBLIC_KEY="$PQ_PUBLIC_KEY" \
RATELMESH_APPLICATION_IDENTITY="$APPLICATION_IDENTITY" \
  "$REPO/scripts/build-macos-update.sh" "$VERSION" "$STAGE/update"

RATELMESH_APPLICATION_IDENTITY="$APPLICATION_IDENTITY" \
RATELMESH_INSTALLER_IDENTITY="$INSTALLER_IDENTITY" \
  "$REPO/scripts/build-macos-installer.sh" \
    "$VERSION" "$STAGE/update/RatelMesh-macOS-$VERSION-update.pkg" "$STAGE/$PACKAGE_NAME"
rm -rf "$STAGE/update"

EXPANDED=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-release-pkg.XXXXXX")
pkgutil --expand-full "$STAGE/$PACKAGE_NAME" "$EXPANDED/package"
PACKAGED_PROVENANCE="$EXPANDED/package/Payload/usr/local/ratelmesh/share/BUILD-PROVENANCE.json"
if [[ "$(plutil -extract sourceCommit raw -o - "$PACKAGED_PROVENANCE")" != "$SOURCE_COMMIT" ||
      "$(plutil -extract sourceDateEpoch raw -o - "$PACKAGED_PROVENANCE")" != "$SOURCE_DATE_EPOCH" ]]; then
  echo "signed package provenance does not match the release source" >&2
  exit 1
fi
"$REPO/scripts/release-macos.sh" identity-check app \
  "$EXPANDED/package/Payload/usr/local/ratelmesh/share/RatelMesh.app" \
  "$APPLICATION_IDENTITY" "$APPLE_TEAM_ID"
"$REPO/scripts/release-macos.sh" identity-check package \
  "$STAGE/$PACKAGE_NAME" "$INSTALLER_IDENTITY" "$APPLE_TEAM_ID"

NOTARY_ARGS=(--keychain-profile "$NOTARY_PROFILE")
if [[ -n "$NOTARY_KEYCHAIN" ]]; then
  NOTARY_ARGS+=(--keychain "$NOTARY_KEYCHAIN")
fi
NOTARY_RESULT="$EXPANDED/notary-result.json"
xcrun notarytool submit "$STAGE/$PACKAGE_NAME" "${NOTARY_ARGS[@]}" \
  --wait --output-format json >"$NOTARY_RESULT"
"$REPO/scripts/release-macos.sh" notary-check "$NOTARY_RESULT"
xcrun stapler staple "$STAGE/$PACKAGE_NAME"
xcrun stapler validate "$STAGE/$PACKAGE_NAME"
spctl --assess --type install -vv "$STAGE/$PACKAGE_NAME"

# Publish the exact GPL source archive that accompanies the bundled `wg`
# binary. It is also inside the package, but a sidecar makes source access
# possible without installing the product.
mkdir -p "$STAGE/sources"
SOURCE_NAME="wireguard-tools-$RATELMESH_WIREGUARD_TOOLS_VERSION.tar.xz"
install -m 644 \
  "$EXPANDED/package/Payload/usr/local/ratelmesh/share/sources/$SOURCE_NAME" \
  "$STAGE/sources/$SOURCE_NAME"
SOURCE_SHA=$(shasum -a 256 "$STAGE/sources/$SOURCE_NAME" | awk '{print $1}')
if [[ "$SOURCE_SHA" != "$RATELMESH_WIREGUARD_TOOLS_SHA256" ]]; then
  echo "packaged wireguard-tools source checksum changed unexpectedly" >&2
  exit 1
fi

go run "$REPO/scripts/update-manifest.go" sign \
  -key "$RELEASE_KEY" \
  -package "$STAGE/$PACKAGE_NAME" \
  -version "$VERSION" \
  -url "$PACKAGE_URL" \
  -minimum-system 13.0 \
  -output "$STAGE/macos/latest.json"

PACKAGE_SHA=$(shasum -a 256 "$STAGE/$PACKAGE_NAME" | awk '{print $1}')
MANIFEST_SHA=$(shasum -a 256 "$STAGE/macos/latest.json" | awk '{print $1}')
printf '{\n  "version": "%s",\n  "sourceCommit": "%s",\n  "sourceDateEpoch": %s,\n  "package": "%s",\n  "packageSHA256": "%s",\n  "manifestSHA256": "%s",\n  "wireGuardToolsSHA256": "%s"\n}\n' \
  "$VERSION" "$SOURCE_COMMIT" "$SOURCE_DATE_EPOCH" "$PACKAGE_NAME" \
  "$PACKAGE_SHA" "$MANIFEST_SHA" "$SOURCE_SHA" >"$STAGE/BUILD-PROVENANCE.json"
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +
go run "$REPO/scripts/publish-directory" "$STAGE" "$OUTDIR"
STAGE=

echo "$OUTDIR/$PACKAGE_NAME"
echo "$OUTDIR/macos/latest.json"
echo "$OUTDIR/sources/$SOURCE_NAME"
