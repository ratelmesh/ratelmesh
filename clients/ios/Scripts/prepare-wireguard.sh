#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST="$ROOT/Dependencies/wireguard-apple"
REVISION=2fec12a6e1f6e3460b6ee483aa00ad29cddadab1

if [ ! -d "$DEST/.git" ] || [ "$(git -C "$DEST" rev-parse HEAD)" != "$REVISION" ]; then
    rm -rf "$DEST"
    mkdir -p "$(dirname "$DEST")"
    git clone https://git.zx2c4.com/wireguard-apple "$DEST"
    git -C "$DEST" checkout --detach "$REVISION"
fi

# The pinned upstream manifest uses platform versions introduced in Package
# Description 5.5 but still declares tools version 5.3. Patch metadata only;
# no WireGuard source is changed.
perl -i -pe 's/swift-tools-version:5\.3/swift-tools-version:5.5/' "$DEST/Package.swift"

# Xcode 26's explicit Clang modules no longer expose BSD integer aliases to a
# module unless the declaring header is imported directly.
if ! grep -q '#include <sys/types.h>' "$DEST/Sources/WireGuardKitC/WireGuardKitC.h"; then
    perl -i -0pe 's/#include "key\.h"/#include <sys\/types.h>\n#include "key.h"/' \
        "$DEST/Sources/WireGuardKitC/WireGuardKitC.h"
fi

# Endpoint/key refreshes must not replace iOS network settings. Reapplying the
# same routes and DNS interrupts established sockets during routine netmap
# updates. Keep this small upstream patch tracked in our repository so a clean
# checkout produces the same WireGuardKit source as release builds.
ADAPTER="$DEST/Sources/WireGuardKit/WireGuardAdapter.swift"
if ! grep -q 'applyNetworkSettings: Bool = true' "$ADAPTER"; then
    git -C "$DEST" apply --unidiff-zero \
        "$ROOT/Patches/wireguard-apple-selective-network-settings.patch"
fi
