# Google Play VpnService declaration

Use this as the submission worksheet. Re-check it against the shipped artifact
and the current Play Console form before every release.

## Declaration answers

- Is VPN the app's core functionality? **Yes.** RatelMesh creates an
  encrypted device-level WireGuard tunnel for private mesh access and an
  optional user-selected internet exit.
- Does the VpnService collect or share personal or sensitive data? The VPN data
  plane does **not** retain or share packet contents. The control plane receives
  the user-entered device name, a device WireGuard public key, reachable network
  endpoints and mesh membership needed to establish the tunnel. Declare these
  consistently in the Data safety form and privacy policy.
- Does it redirect or manipulate traffic for monetization? **No.** There is no
  advertising SDK and no traffic-based monetization.
- Encryption: traffic from the device to the selected WireGuard peer or exit is
  encrypted with WireGuard.

## Required review video, 90 seconds or less

Record a physical Android device with a fresh install:

1. Open RatelMesh and enter review credentials.
2. Tap Connect. Show the complete in-app VPN disclosure before accepting it.
3. Tap **Not now**, then tap Connect again to prove the disclosure returns.
4. Tap **Accept and continue**, approve Android's VPN dialog and show Connected.
5. Open a peer or select an exit, then disconnect from the persistent
   notification or the app.

Upload the recording to the location accepted by Play Console and submit its
URL with the VpnService declaration. The store listing must explicitly state
that the app uses Android VpnService for its encrypted mesh/VPN tunnel.

Official policy: <https://support.google.com/googleplay/android-developer/answer/12564964>
