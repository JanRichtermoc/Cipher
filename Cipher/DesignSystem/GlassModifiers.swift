//
//  GlassModifiers.swift
//  Cipher
//

import SwiftUI

extension View {
    /// Liquid Glass on functional chrome. Falls back gracefully if unavailable.
    @ViewBuilder
    func cipherGlass(in shape: some Shape = Capsule()) -> some View {
        self.glassEffect(.regular, in: shape)
    }

    @ViewBuilder
    func cipherGlassClear(in shape: some Shape = Capsule()) -> some View {
        self.glassEffect(.clear, in: shape)
    }
}

struct GlassIconButton: View {
    let systemName: String
    var size: CGFloat = 20
    var role: ButtonRole? = nil
    let action: () -> Void

    var body: some View {
        Button(role: role, action: action) {
            Image(systemName: systemName)
                .font(.system(size: size, weight: .semibold))
                .frame(width: 44, height: 44)
                .contentShape(Circle())
        }
        .buttonStyle(.glass)
        .accessibilityLabel(Text(systemName))
    }
}

struct PrimaryGlassButton: View {
    let title: LocalizedStringKey
    var systemImage: String? = nil
    var isEnabled: Bool = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: CipherTheme.spacingS) {
                if let systemImage {
                    Image(systemName: systemImage)
                }
                Text(title)
                    .fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
        }
        .buttonStyle(.glassProminent)
        .tint(CipherTheme.accent)
        .disabled(!isEnabled)
        .opacity(isEnabled ? 1 : 0.5)
    }
}

struct SecondaryGlassButton: View {
    let title: LocalizedStringKey
    var systemImage: String? = nil
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: CipherTheme.spacingS) {
                if let systemImage {
                    Image(systemName: systemImage)
                }
                Text(title)
                    .fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
        }
        .buttonStyle(.glass)
    }
}
