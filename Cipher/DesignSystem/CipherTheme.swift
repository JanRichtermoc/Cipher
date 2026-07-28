//
//  CipherTheme.swift
//  Cipher
//

import SwiftUI

enum CipherTheme {
    static let accent = Color(red: 0.12, green: 0.62, blue: 0.58)
    static let accentDeep = Color(red: 0.08, green: 0.42, blue: 0.48)
    static let sentBubble = Color(red: 0.12, green: 0.55, blue: 0.52)
    static let receivedBubble = Color(.secondarySystemFill)
    static let systemText = Color.secondary
    static let danger = Color.red
    static let warning = Color.orange
    static let success = Color.green

    static let spacingXS: CGFloat = 4
    static let spacingS: CGFloat = 8
    static let spacingM: CGFloat = 12
    static let spacingL: CGFloat = 16
    static let spacingXL: CGFloat = 24
    static let spacingXXL: CGFloat = 32

    static let radiusS: CGFloat = 10
    static let radiusM: CGFloat = 16
    static let radiusL: CGFloat = 22
    static let radiusPill: CGFloat = 100

    static let avatarS: CGFloat = 36
    static let avatarM: CGFloat = 48
    static let avatarL: CGFloat = 72
    static let avatarXL: CGFloat = 96
}

extension Font {
    static let cipherSafetyNumber = Font.system(.body, design: .monospaced).weight(.medium)
}
