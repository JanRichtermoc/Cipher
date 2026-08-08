//
//  PhotoAttachment.swift
//  Cipher
//
//  Copyright (C) 2026 Jan Richter
//  SPDX-License-Identifier: AGPL-3.0-only
//

import CipherCrypto
import Foundation
import UIKit

/// Turns a picked image into the bytes that get encrypted and uploaded (P6.S04).
///
/// ## Re-encoding is a privacy control, not a size optimisation
///
/// A photo straight out of the library carries EXIF: the coordinates where it was taken, the
/// device that took it, and the moment it was taken. Sending the original file would put all of
/// that inside the attachment — end-to-end encrypted, so the relay never sees it, and delivered
/// intact to whoever receives it and to anything they later share it with. `THREAT_MODEL.md`
/// §4's whole position on metadata is that the safe amount is the amount that was never
/// collected, and the same argument applies to metadata this app would otherwise forward.
///
/// Decoding to a bitmap and re-encoding as JPEG produces a file built from pixels alone. There
/// is no metadata to strip because none is carried over.
///
/// ## And it is what makes the size bound reachable
///
/// `AttachmentCipher.maxPlaintextBytes` is the ceiling, and a modern phone photo can exceed it.
/// Refusing those outright would be a feature that fails on the pictures people actually take,
/// so the encoder steps quality down and then dimensions down until the result fits, and only
/// gives up if it still does not.
enum PhotoAttachment {

    /// Longest edge of the image that is sent.
    ///
    /// Well above what a phone screen shows and well below what a modern camera produces. The
    /// bound exists so the decoded bitmap is bounded too: the source is chosen by the user, and
    /// an image with enormous dimensions is a memory spike before any of it is encrypted.
    static let maxPixelEdge: CGFloat = 2048

    /// JPEG qualities tried in order. The first that fits wins; if none does, the image is
    /// halved and the ladder is tried again.
    private static let qualities: [CGFloat] = [0.85, 0.7, 0.5]

    /// How many times the image may be halved before this gives up. Four halvings take a
    /// 2048-pixel edge to 128, which no plausible photo exceeds the byte ceiling at — the bound
    /// exists so a pathological input cannot loop, not because it is expected to be reached.
    private static let maxDownscales = 4

    /// Re-encodes `data` as a JPEG that fits ``AttachmentCipher/maxPlaintextBytes``, or nil if
    /// it is not an image this device can decode.
    static func prepare(_ data: Data) -> Data? {
        guard let decoded = UIImage(data: data) else { return nil }

        var image = resized(decoded, toLongestEdge: maxPixelEdge)
        for _ in 0...maxDownscales {
            for quality in qualities {
                guard let encoded = image.jpegData(compressionQuality: quality) else {
                    return nil
                }
                if encoded.count <= AttachmentCipher.maxPlaintextBytes { return encoded }
            }
            let edge = max(image.size.width, image.size.height) / 2
            guard edge >= 1 else { return nil }
            image = resized(image, toLongestEdge: edge)
        }
        return nil
    }

    /// Scales `image` so its longest edge is at most `edge`, drawing it into a fresh bitmap.
    ///
    /// Always redraws, even when the image is already small enough: the draw is what discards
    /// the original's metadata and its orientation flag, and skipping it for small images would
    /// mean the privacy property held only for large ones.
    private static func resized(_ image: UIImage, toLongestEdge edge: CGFloat) -> UIImage {
        let longest = max(image.size.width, image.size.height)
        let scale = longest > edge ? edge / longest : 1
        let size = CGSize(
            width: max(1, (image.size.width * scale).rounded()),
            height: max(1, (image.size.height * scale).rounded()))

        let format = UIGraphicsImageRendererFormat.default()
        // Points, not device pixels: the size above is already the pixel count that is wanted,
        // and a scale of 2 or 3 would silently produce four or nine times the bytes.
        format.scale = 1
        format.opaque = true
        return UIGraphicsImageRenderer(size: size, format: format).image { _ in
            image.draw(in: CGRect(origin: .zero, size: size))
        }
    }
}
