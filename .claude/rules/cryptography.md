---
paths:
  - "CipherCrypto/**/*"
  - "CipherCryptoTests/**/*"
  - "Vendor/libsignal/**/*"
  - "Pods/LibSignalClient/**/*"
  - "Podfile"
  - "Podfile.lock"
---

# Cryptography and libsignal

- Read the implementation plan §0.2/§0.6, `docs/THREAT_MODEL.md`, applicable `docs/AUDIT.md` rows,
  and `Vendor/libsignal/DECISIONS.md` before editing.
- Use the pinned LibSignalClient and CryptoKit only. Do not invent cryptography, add a crypto
  dependency, move a pin, or update dependency bytes outside explicitly approved supply-chain work.
- Keep all libsignal access on `@CryptoActor`; do not add `@unchecked Sendable` to bypass isolation.
- No LibSignalClient type may escape `CipherCrypto`'s public API, including through a thrown error.
- Never expose private key material, plaintext messages, protocol records, raw addresses, safety
  numbers, or secret-derived buffers in logs, fixtures, documentation, or chat.
- Preserve session-bound sender attribution, exact-key identity acceptance, fail-closed wire parsing,
  encrypted-at-rest storage, crash-safe erasure, and locked group/single-device boundaries.
- Run focused crypto tests and the API-boundary gate before the full repository verification; prove
  any new test ran by name.
