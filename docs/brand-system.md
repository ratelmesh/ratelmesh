# RatelMesh product brand system

The accepted honey-badger Mesh mark is the source of truth for every product
surface. RatelMesh should look like a private network that its owner can
understand and control, not like a generic VPN or antivirus product.

## Visual idea

**Trusted devices connected by visible, verified paths.**

Use named devices, private services, user-owned exits, nodes and restrained
route lines. Avoid shields, padlocks, anonymous globes, hacker terminals,
generic robot faces and decorative security theatre.

## Color

| Token | Value | Use |
|---|---:|---|
| Ratel Black | `#0B0F14` | Primary dark canvas and launcher tile |
| Ratel White | `#F4F7F9` | Primary text and light surfaces |
| Mesh Cyan | `#20B9E8` | Brand identity, verified routes, active nodes |
| Accessible Cyan | `#006A8C` | Cyan text and controls on light surfaces |
| Surface | `#111820` | Raised dark cards |
| Surface Raised | `#18222C` | Selected and interactive dark cards |
| Outline Slate | `#42515C` | Borders and inactive routes |
| Paper | `#EEF3F5` | Light technical surfaces |
| Muted | `#8C9AA5` | Secondary text |
| Healthy | `#16956C` | Confirmed healthy state only |
| Warning | `#D8902F` | Actionable degraded state only |
| Critical | `#D65353` | Confirmed failure or destructive action |

Mesh Cyan is not ambient decoration. Reserve it for brand identity, primary
actions and paths that are currently verified. Status colors never replace the
brand color.

## Type and layout

- Use the platform system sans family for product UI. Use a restrained
  monospace face for addresses, versions, protocols and route evidence.
- Lead with a direct thesis, then evidence. Prefer sentence case.
- Use an 8-point spacing rhythm.
- Website content uses a maximum 1360 px shell. Product panels use 12–24 px
  gaps and 16–24 px padding.
- Corners are precise rather than pill-heavy: 6–12 px for controls and
  technical cards, up to 24 px only for large narrative panels.
- One-pixel rules and route lines establish hierarchy. Glows stay local to an
  active node or path.

## Marks

- 64 px and above: `icon-primary.svg` on light surfaces or
  `icon-on-dark.svg` on dark surfaces.
- 16–63 px: `icon-micro-tile.svg`.
- OS-controlled one-color surfaces: `icon-monochrome.svg` or its mechanically
  derived platform asset.
- Horizontal headers use the matching on-light or on-dark lockup.
- Never place the mark inside an added shield, lock, hexagon or VPN badge.
- Never substitute an SF Symbol, Material shield or platform security glyph for
  the RatelMesh mark.

## Product components

- **Identity:** device-held key and verified owner.
- **Device:** a named physical endpoint.
- **Policy:** explicit, revocable access.
- **Route:** a visible direct, relay or exit path.
- **Evidence:** health, latency, handshake and diagnostic result.

The same hierarchy appears on the website, desktop menus and mobile clients.
Platform conventions may change the container, but not the mark, palette or
meaning of a state.

## Motion

- State transitions: 140–180 ms.
- A verified route may advance one small signal every 2.4 seconds.
- A status indicator may breathe once after a state change.
- No continuous particle fields, scanning effects, bouncing nodes or parallax.
- Freeze route animation and remove transforms when reduced motion is enabled.

## Imagery

Hero imagery may show real devices in a dark, cinematic environment connected
by controlled Mesh Cyan paths. Keep useful negative space for live HTML text.
Do not render product copy, the RatelMesh wordmark or security claims into the
image. Do not use green as the brand color.
