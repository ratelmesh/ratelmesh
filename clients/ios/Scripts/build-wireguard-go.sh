#!/bin/sh
set -eu

CHECKOUT_ROOT="$SRCROOT/Dependencies/wireguard-apple"
SOURCE="$CHECKOUT_ROOT/Sources/WireGuardKitGo"

if [ ! -f "$SOURCE/Makefile" ]; then
    echo "error: WireGuardKitGo checkout not found at $SOURCE" >&2
    echo "Run Scripts/prepare-wireguard.sh before building PacketTunnel." >&2
    exit 1
fi

# WireGuard's Makefile names both device and simulator builds GOOS=ios. Xcode's
# SDKROOT and deployment flags still select the correct clang target.
make -C "$SOURCE" build \
    PLATFORM_NAME=iphoneos \
    SDKROOT="$SDKROOT" \
    ARCHS="${ARCHS:-arm64}" \
    CONFIGURATION_BUILD_DIR="$CONFIGURATION_BUILD_DIR" \
    CONFIGURATION_TEMP_DIR="$CONFIGURATION_TEMP_DIR" \
    DEPLOYMENT_TARGET_CLANG_FLAG_NAME="${DEPLOYMENT_TARGET_CLANG_FLAG_NAME:-}" \
    DEPLOYMENT_TARGET_CLANG_ENV_NAME="${DEPLOYMENT_TARGET_CLANG_ENV_NAME:-}"
