# Cipher — licensing and third-party notices

## Cipher

Copyright (C) 2026 Jan Richter

Cipher is free software: you can redistribute it and/or modify it under the terms of the
**GNU Affero General Public License, version 3** as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details. The full text is in [LICENSE](LICENSE).

### Why AGPL

Cipher links **libsignal**, which is licensed AGPL-3.0-only. Linking it makes Cipher a
derivative work, so Cipher is AGPL-3.0 in its entirety. Under AGPL §13, anyone who interacts
with this software over a network is entitled to receive its complete corresponding source.

This is a deliberate choice, not an accident of dependency selection. The alternative —
reimplementing the Signal Protocol to avoid the licence — would mean writing our own
cryptography, which is exactly what this project refuses to do.

---

## Third-party components

### libsignal

- **Copyright** © Signal Messenger, LLC
- **Licence** AGPL-3.0-only
- **Source** https://github.com/signalapp/libsignal
- **Version** `v0.99.1` (commit `97801d22dcf9f5bf714f7b8fa3212cdc973ae1c8`)

libsignal provides the Signal Protocol implementation: PQXDH key agreement, the Double
Ratchet, sealed sender, and the zkgroup primitives. Cipher uses it unmodified. The exact
pins and their verification record are in
[`Vendor/libsignal/PINS.env`](Vendor/libsignal/PINS.env) and
[`Vendor/libsignal/DECISIONS.md`](Vendor/libsignal/DECISIONS.md).

libsignal in turn bundles further third-party code. Its own acknowledgements are shipped in
the pod at `Pods/LibSignalClient/acknowledgments/acknowledgments-ios.plist` and must be
surfaced in the app's About screen before release.

> Signal's own position, from their README: *"Use outside of Signal is unsupported."*
> Cipher's use of libsignal is unaffiliated with and unendorsed by Signal Messenger, LLC.
> Cipher is not Signal, is not interoperable with Signal, and must not be presented as either.

### Build tooling

CocoaPods and its gem dependency tree are build-time only and are not distributed with the
app. Versions are pinned in [`Gemfile.lock`](Gemfile.lock).

---

## Obligations this project must meet

1. **Publish complete corresponding source** for every distributed build, under AGPL-3.0.
2. **Preserve this notice and the licence text** in all copies.
3. **Surface libsignal's acknowledgements** in the app's About screen.
4. **Offer source to network users** (§13) if Cipher's server component is ever deployed such
   that users interact with modified server-side software.
5. **Do not represent Cipher as Signal**, or as affiliated with Signal Messenger, LLC.

Export note: Cipher contains encryption. `ITSAppUsesNonExemptEncryption` must be declared and,
depending on jurisdiction and distribution channel, a self-classification report may be
required. That is a legal determination, not an engineering one.
