#!/bin/sh
set -eu

CHECKOUT_ROOT="$SRCROOT/Dependencies/wireguard-apple"
SOURCE="$CHECKOUT_ROOT/Sources/WireGuardKitGo"

if [ ! -f "$SOURCE/Makefile" ]; then
    echo "error: WireGuardKitGo checkout not found at $SOURCE" >&2
    echo "Run Scripts/prepare-wireguard.sh before building PacketTunnelMac." >&2
    exit 1
fi

make -C "$SOURCE" build \
    PLATFORM_NAME=macosx \
    SDKROOT="$SDKROOT" \
    ARCHS="${ARCHS:-arm64 x86_64}" \
    CONFIGURATION_BUILD_DIR="$CONFIGURATION_BUILD_DIR" \
    CONFIGURATION_TEMP_DIR="$CONFIGURATION_TEMP_DIR" \
    DEPLOYMENT_TARGET_CLANG_FLAG_NAME="${DEPLOYMENT_TARGET_CLANG_FLAG_NAME:-mmacosx-version-min}" \
    DEPLOYMENT_TARGET_CLANG_ENV_NAME="${DEPLOYMENT_TARGET_CLANG_ENV_NAME:-MACOSX_DEPLOYMENT_TARGET}"
