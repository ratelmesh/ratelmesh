#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf '%s\n' "usage: $0 ANDROID_HOME" >&2
    exit 2
fi

SOURCE_SDK=$1
CACHE_ROOT=${RATELMESH_ANDROID_ARM64_CACHE:-"${XDG_CACHE_HOME:-$HOME/.cache}/ratelmesh-android-arm64"}
OVERLAY="$CACHE_ROOT/android-sdk-native-llvm-v6"

command -v clang >/dev/null 2>&1 || { printf '%s\n' "Native clang is required (Ubuntu: apt install clang lld llvm)" >&2; exit 1; }
command -v clang++ >/dev/null 2>&1 || { printf '%s\n' "Native clang++ is required" >&2; exit 1; }
command -v ld.lld >/dev/null 2>&1 || { printf '%s\n' "Native ld.lld is required" >&2; exit 1; }
test -d "$SOURCE_SDK/ndk" || { printf '%s\n' "Android NDK is missing from $SOURCE_SDK" >&2; exit 1; }

mkdir -p "$CACHE_ROOT"
if [ ! -f "$OVERLAY/.ratelmesh-ready" ]; then
    OVERLAY_TMP=$(mktemp -d "$CACHE_ROOT/android-sdk.XXXXXX")
    for entry in "$SOURCE_SDK"/*; do
        name=$(basename "$entry")
        [ "$name" = "ndk" ] && continue
        ln -s "$entry" "$OVERLAY_TMP/$name"
    done
    mkdir -p "$OVERLAY_TMP/ndk"
    cp -al "$SOURCE_SDK/ndk/." "$OVERLAY_TMP/ndk/"
    find "$OVERLAY_TMP/ndk" -path '*/toolchains/llvm/prebuilt/linux-x86_64/bin/clang' -o -path '*/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++' | while IFS= read -r tool; do
        relative=${tool#"$OVERLAY_TMP/"}
        source_tool="$SOURCE_SDK/$relative"
        ndk_prebuilt=${source_tool%/bin/*}
        native=$(basename "$tool")
        unlink "$tool"
        printf '%s\n' '#!/bin/sh' 'case " $* " in *" -shared "*|*" -rdynamic "*) set -- --rtlib=compiler-rt "$@" ;; esac' "exec /usr/bin/$native --sysroot='$ndk_prebuilt/sysroot' -resource-dir '$ndk_prebuilt/lib/clang/18' \"\$@\"" > "$tool"
        chmod 755 "$tool"
    done
    for native in llvm-ar llvm-ranlib llvm-nm llvm-objcopy llvm-readelf llvm-strip ld.lld; do
        find "$OVERLAY_TMP/ndk" -path "*/toolchains/llvm/prebuilt/linux-x86_64/bin/$native" | while IFS= read -r tool; do
            command -v "$native" >/dev/null 2>&1 || continue
            unlink "$tool"
            printf '%s\n' '#!/bin/sh' "exec /usr/bin/$native \"\$@\"" > "$tool"
            chmod 755 "$tool"
        done
    done
    : > "$OVERLAY_TMP/.ratelmesh-ready"
    mv "$OVERLAY_TMP" "$OVERLAY"
fi

printf '%s\n' "$OVERLAY"
