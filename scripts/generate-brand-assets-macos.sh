#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
brand="$repo/assets/brand/ratelmesh-brand-v3"
png="$brand/png"
work=$(mktemp -d "${TMPDIR:-/tmp}/ratelmesh-brand-v3.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

test "$(uname -s)" = Darwin || {
  echo "brand raster generation requires macOS" >&2
  exit 1
}

render() {
  source=$1
  output=$2
  width=$3
  height=$4
  base="$work/$(basename "$source").png"
  sips -s format png "$source" --out "$base" >/dev/null
  sips -z "$height" "$width" "$base" --out "$output" >/dev/null
}

mkdir -p "$png"

render "$brand/icon-primary.svg" "$png/icon-primary.svg.png" 512 512
render "$brand/icon-primary.svg" "$png/icon-primary-1024.png" 1024 1024
render "$brand/icon-primary.svg" "$png/icon-primary-512.png" 512 512
render "$brand/icon-primary.svg" "$png/icon-primary-64.png" 64 64
render "$brand/icon-on-dark.svg" "$png/icon-on-dark.svg.png" 512 512
render "$brand/icon-on-dark.svg" "$png/icon-on-dark-1024.png" 1024 1024
render "$brand/icon-monochrome.svg" "$png/icon-monochrome.svg.png" 512 512
render "$brand/icon-monochrome.svg" "$png/icon-monochrome-1024.png" 1024 1024
render "$brand/icon-micro-tile.svg" "$png/icon-micro-tile.svg.png" 512 512
render "$brand/icon-micro-tile.svg" "$png/icon-micro-tile-512.png" 512 512
render "$brand/icon-micro-tile.svg" "$png/favicon-16.png" 16 16
render "$brand/icon-micro-tile.svg" "$png/favicon-32.png" 32 32
render "$brand/icon-micro-tile.svg" "$png/apple-touch-icon-180.png" 180 180

for variant in on-light on-dark monochrome; do
  render \
    "$brand/logo-horizontal-$variant.svg" \
    "$png/logo-horizontal-$variant.svg.png" \
    1200 300
  install -m 644 \
    "$png/logo-horizontal-$variant.svg.png" \
    "$png/logo-horizontal-$variant-1200x300.png"
done

website_brand="$repo/website/public/brand"
mkdir -p "$website_brand"
for file in \
  icon-primary.svg \
  icon-on-dark.svg \
  icon-micro-tile.svg \
  icon-monochrome.svg \
  logo-horizontal-on-light.svg \
  logo-horizontal-on-dark.svg \
  logo-horizontal-monochrome.svg; do
  install -m 644 "$brand/$file" "$website_brand/$file"
done
for file in favicon-16.png favicon-32.png apple-touch-icon-180.png; do
  install -m 644 "$png/$file" "$website_brand/$file"
done
install -m 644 "$png/icon-primary-64.png" "$repo/website/public/favicon.png"

install -m 644 "$png/icon-primary-1024.png" \
  "$repo/clients/macos-menubar/AppIcon.png"
install -m 644 "$png/icon-on-dark-1024.png" \
  "$repo/clients/macos-menubar/BrandMarkDark.png"
install -m 644 "$png/icon-on-dark-1024.png" \
  "$repo/clients/ios/RatelMesh/Assets.xcassets/BrandMarkDark.imageset/BrandMarkDark-1024.png"

# App Store icons must be opaque. Rendering through a maximum-quality JPEG
# intentionally composites the transparent SVG canvas onto white, then returns
# to PNG for the asset catalog.
sips -s format jpeg -s formatOptions 100 "$brand/icon-primary.svg" \
  --out "$work/AppIcon-1024.jpg" >/dev/null
sips -s format png "$work/AppIcon-1024.jpg" \
  --out "$work/AppIcon-1024.png" >/dev/null
sips -z 1024 1024 "$work/AppIcon-1024.png" \
  --out "$repo/clients/ios/RatelMesh/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png" >/dev/null

iconset="$work/RatelMesh.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
  render "$brand/icon-primary.svg" "$iconset/icon_${size}x${size}.png" "$size" "$size"
  doubled=$((size * 2))
  render "$brand/icon-primary.svg" "$iconset/icon_${size}x${size}@2x.png" "$doubled" "$doubled"
done
iconutil -c icns "$iconset" -o "$repo/clients/macos-menubar/RatelMesh.icns"

for density_size in \
  mdpi:48 \
  hdpi:72 \
  xhdpi:96 \
  xxhdpi:144 \
  xxxhdpi:192; do
  density=${density_size%%:*}
  size=${density_size##*:}
  render \
    "$brand/icon-primary.svg" \
    "$repo/clients/android/app/src/main/res/mipmap-$density/ic_launcher.png" \
    "$size" "$size"
done

echo "RatelMesh v3 brand assets generated"
