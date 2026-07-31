# App Review response: VPN data handling (en-US)

Copy the text below into both the App Review message reply and the App Review
Information notes. Reconfirm the production hosting region and deployed
service behavior before sending it.

---

Hello App Review,

RatelMesh contains VPN functionality. It uses Apple's Network Extension
packet-tunnel API and WireGuard to connect a device to a private RatelMesh
tenant. It can also route traffic through an exit device that the tenant has
explicitly authorized.

1. **What user information is collected using the VPN?** RatelMesh does not
   collect or store browsing history, complete DNS query history, URLs, webpage
   content, passwords, or plaintext packet payloads carried by the VPN. The
   packet tunnel processes traffic on the device only to encrypt, decrypt, and
   route it. To provide the VPN, the RatelMesh control plane receives the
   user-entered device name, an app-generated device identifier, the WireGuard
   public key, platform and app version, assigned private mesh address, online
   and last-seen state, configured routes, public or relay endpoints, and the
   selected exit. The WireGuard private key and session credential remain in
   the device Keychain. If the user explicitly grants Location access, the app
   sends only a coarse region; exact coordinates remain on the device.
   Handshake times and byte counters are evaluated on the device and are not
   sent to analytics.

2. **Why is this information collected?** It is used only to enroll and
   authenticate the device, create and distribute its private-network
   configuration, discover permitted peers, configure routes, display
   connection state, operate the user's selected exit, and diagnose
   connectivity when the user requests it. It is not used for advertising,
   cross-app tracking, marketing profiles, or sale.

3. **Is it shared with third parties, and where is it stored?** RatelMesh does
   not sell this information or share it with third parties for their own
   purposes. Operational control-plane records are stored on RatelMesh
   infrastructure in Tokyo, Japan, and retained only while operationally
   necessary. Infrastructure service providers process them only under
   RatelMesh's instructions. VPN traffic is delivered only to peers and any
   relay or exit authorized by the user's RatelMesh tenant. A relay transports
   encrypted WireGuard packets and necessary transport metadata. A selected
   exit necessarily sees destination IP addresses, timing, and traffic volume,
   as any VPN gateway or internet provider would; HTTPS content remains
   end-to-end encrypted. These are tenant-authorized network participants, not
   advertising or data-broker partners. RatelMesh does not give them a browsing
   database and does not persist tunnel contents or DNS browsing history.

Network Doctor is optional and runs only after the user starts it following an
in-app disclosure. Its bounded probes contact the configured Coordinator,
Relay, DNS resolver, Cloudflare IP-reachability endpoints, and configured media
canaries. Those endpoints can observe the source or exit public IP as part of a
normal network request. RatelMesh does not persist that observed public IP, and
the shareable diagnostic report redacts target and interface identifiers.

Please let us know if any additional detail or a review demonstration is
needed.
