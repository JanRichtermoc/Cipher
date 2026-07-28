//
//  PeerAddress.swift
//  CipherCrypto
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient

/// Which installation a message is for: an identifier plus a device.
///
/// The boundary replacement for libsignal's `ProtocolAddress`, which is a `ClonableHandleOwner`
/// — it owns a Rust pointer freed from `deinit`, so a copy the UI held could be released off
/// the crypto queue. This is two stored fields and nothing else.
///
/// ## `deviceId` is here even though wire v1 has no such field
///
/// The store keys every session, prekey and trust decision on `name.deviceId`, because that
/// is what libsignal's stores are addressed by. The *wire* omits it deliberately: locked
/// decision §0.2.5 fixes this build at one device per identifier, and adding a second would
/// be a `wireVersion` 2 change rather than something that leaks in unnoticed. Keeping the
/// field here — pinned to `primaryDevice` unless a caller says otherwise — means that change
/// is a wire-format decision later, not a store migration as well.
public struct PeerAddress: Sendable, Hashable {

    /// The only device id wire v1 can address. Named rather than written as a bare `1` so
    /// the places that assume single-device are greppable when multi-device is designed.
    public static let primaryDevice: UInt32 = 1

    public let serviceId: ServiceIdentifier
    public let deviceId: UInt32

    public init(serviceId: ServiceIdentifier, deviceId: UInt32 = PeerAddress.primaryDevice) {
        self.serviceId = serviceId
        self.deviceId = deviceId
    }

    public init(aci uuid: UUID, deviceId: UInt32 = PeerAddress.primaryDevice) {
        self.init(serviceId: ServiceIdentifier(kind: .aci, uuid: uuid), deviceId: deviceId)
    }
}

// MARK: - libsignal bridge

extension PeerAddress {

    /// Builds the library's address type. Crypto-queue only, like everything that touches a
    /// libsignal handle.
    internal func makeProtocolAddress() throws -> ProtocolAddress {
        CryptoActor.assertIsolated()
        return try ProtocolAddress(name: serviceId.canonicalString, deviceId: deviceId)
    }
}
