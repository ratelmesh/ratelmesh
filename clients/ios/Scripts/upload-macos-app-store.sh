#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ "$#" -ne 1 ]; then
    echo "usage: $0 ARCHIVE_PATH" >&2
    exit 2
fi

ARCHIVE_PATH=$1
"$ROOT/Scripts/verify-macos-archive.sh" "$ARCHIVE_PATH"

UPLOAD_OPTIONS=$(mktemp "${TMPDIR:-/tmp}/ratelmesh-macos-upload-options.XXXXXX")
trap 'rm -f "$UPLOAD_OPTIONS"' EXIT INT TERM
cp "$ROOT/ExportOptions-AppStore.plist" "$UPLOAD_OPTIONS"
plutil -replace destination -string upload "$UPLOAD_OPTIONS"

xcodebuild -allowProvisioningUpdates \
    -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportPath "${TMPDIR:-/tmp}/ratelmesh-macos-upload" \
    -exportOptionsPlist "$UPLOAD_OPTIONS"
