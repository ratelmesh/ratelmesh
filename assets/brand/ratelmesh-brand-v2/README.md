# RatelMesh brand v2

V2 keeps the black/white/cyan direction but corrects the production issues found in v1.

## What changed

- Broader, lower honey-badger skull with small rounded ears.
- Pale crown flows continuously into the side bands to carry the species identity; the sword-like central stripe is gone.
- Rounded lower contour avoids the generic cybersecurity-shield silhouette.
- Six nodes form one connected graph instead of two disconnected side chains.
- Mesh geometry is contained inside the pale crown, so it reads as an embedded system rather than headphones or a face cage.
- Horizontal lockups are transparent.
- Wordmarks are custom SVG paths with no font dependency.
- The micro mark uses a fixed dark rounded tile so it survives dark browser tabs.

## Files

- `icon-primary.svg` — transparent icon for light and neutral backgrounds.
- `icon-on-dark.svg` — transparent icon with a controlled outline for dark backgrounds.
- `icon-micro-tile.svg` — favicon and app-tile source.
- `logo-horizontal-on-dark.svg` — transparent horizontal lockup for dark backgrounds.
- `logo-horizontal-on-light.svg` — transparent horizontal lockup for light backgrounds.
- `icon-monochrome.svg` — transparent one-ink icon; set CSS `color` when embedded inline.
- `logo-horizontal-monochrome.svg` — transparent one-ink horizontal lockup.

## Color tokens

- Ratel Black: `#0B0F14`
- Mesh Cyan: `#20B9E8`
- Accessible Mesh Cyan on white: `#087EA4`
- Ratel White: `#F4F7F9`
- Dark-background outline: `#42515C`

## Responsive usage

- 64 px and above: use `icon-primary.svg` or `icon-on-dark.svg`.
- 16–63 px: use `icon-micro-tile.svg`; do not shrink the full Mesh graph into a favicon.
- Use `logo-horizontal-on-light.svg` on white and light neutral surfaces.
- Use `logo-horizontal-on-dark.svg` on `#070A0E` or similarly dark surfaces.
- Use the monochrome files for one-ink printing, laser engraving, embossing, or embroidery.

## Raster exports

The `png/` folder contains 1024, 512, 180, 64, 32, and 16 px icon exports plus 1200×300 horizontal lockups. The `.svg.png` files are render-QA intermediates; named size exports are the delivery files.
