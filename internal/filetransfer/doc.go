// Package filetransfer is the transport-independent core for one-file,
// end-to-end encrypted transfers.
//
// The package deliberately has no Coordinator, Relay, WireGuard, HTTP, or
// platform-keychain dependency. Callers provision a dedicated Ed25519/X25519
// file-transfer identity. An offline Tenant authority signs its tenant,
// device, version, and validity binding; WireGuard keys must never be passed
// as file-transfer keys. VerifyDeviceBinding enforces the caller's monotonic
// key-version floor before a Peer can be used.
//
// A sender encrypts the manifest and random content key to the bound recipient
// with ephemeral X25519, HKDF-SHA256, and AES-256-GCM. Its Ed25519 signature
// covers both device-binding digests, both identities, the ephemeral key,
// unlinkable keyed manifest commitment, transfer identifier, expiration, nonce,
// and ciphertext.
// Each content chunk has a deterministic per-transfer/per-index nonce and AAD
// that binds the keyed manifest commitment, index, and exact plaintext size.
//
// Receiver state contains an authenticated completion bitmap. On restart,
// every locally completed chunk is hashed again before it is trusted. Final
// publication uses an os.Root-selected destination and no-overwrite atomic
// link after complete size and hash verification. The Coordinator may carry
// opaque offers and resume tokens, but never plaintext filenames, content
// keys, file bytes, private keys, or passwords.
package filetransfer
