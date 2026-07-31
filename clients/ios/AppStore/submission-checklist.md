# App Store submission checklist

## App record

- Platforms: iOS and iPadOS; opt in to Apple silicon Mac availability.
- Primary language: English (U.S.).
- Bundle ID: `com.ratelmesh.ios`.
- Name: RatelMesh.
- SKU: `RATELMESH-IOS-001`.
- User access: Full Access.
- Developer name: use the verified organization name unless Apple has approved
  a registered RatelMesh trade name.

## Binary

- Version: 0.2.39.
- Build: 240.
- Main bundle: `com.ratelmesh.ios`.
- Packet Tunnel bundle: `com.ratelmesh.ios.PacketTunnel`.
- Confirm `get-task-allow=false` and `beta-reports-active=true` in both
  production provisioning profiles.
- Confirm `ITSAppUsesNonExemptEncryption=false` while the release uses only
  published standard cryptography and excludes France.
- Confirm `ITSEncryptionExportComplianceCode` is absent unless Apple has
  approved documentation and issued a value.
- Run `Scripts/verify-archive.sh` before upload.

## Privacy answers

Collected and linked to the user for App Functionality, never for tracking:

- Coarse Location.
- Device ID.
- Other User Content (the user-supplied device name).

No data is used for tracking. Keep these answers aligned with
`Shared/PrivacyInfo.xcprivacy` and `https://ratelmesh.com/privacy`.

## Export compliance

- The app implements encryption outside the Apple operating system, including
  WireGuard and published standard post-quantum algorithms.
- Do not answer that the app uses no encryption or only Apple's encryption.
- Answer Apple's encryption questionnaire with standard algorithms and no
  proprietary algorithms.
- For the first release, exclude France. In this scope Apple does not require a
  document upload; `ITSAppUsesNonExemptEncryption=false` records that
  document-upload exemption rather than an absence of encryption.
- Reassess U.S. self-classification/reporting obligations outside App Store
  Connect, and complete the French declaration before adding France.

## Review and release

- Generate a fresh one-time App Review enrollment code with an expiration long
  enough for review and place it only in App Review Information.
- Add iPhone and iPad screenshots from the signed release UI.
- Use the standard Apple EULA.
- Primary category: Utilities; secondary category: Productivity.
- Age rating: answer the current questionnaire from actual app behavior; do not
  mark the app as Made for Kids.
- Release manually after approval so production availability can be verified.
- Do not submit until the account holder has personally accepted any newly
  presented Apple legal agreements.
