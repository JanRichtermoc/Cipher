//
//  OnboardingFlowView.swift
//  Cipher
//

import SwiftUI

struct OnboardingFlowView: View {
    @Environment(AppSession.self) private var session
    @State private var step: Step = .welcome

    enum Step: Hashable {
        case welcome
        case privacy
    }

    var body: some View {
        NavigationStack {
            Group {
                switch step {
                case .welcome:
                    WelcomeView(onContinue: { step = .privacy })
                case .privacy:
                    PrivacyCarouselView(onContinue: {
                        session.completeOnboarding()
                    })
                }
            }
            .toolbar {
                #if DEBUG
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Skip to App") {
                        session.debugSkipToMain = true
                        session.hasCompletedOnboarding = true
                        try? session.signInForDevelopment()
                        session.debugUnlockWithoutAuthentication()
                    }
                    .font(.caption)
                }
                #endif
            }
        }
    }
}

struct WelcomeView: View {
    var onContinue: () -> Void

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    CipherTheme.accentDeep.opacity(0.35),
                    Color(.systemBackground),
                    CipherTheme.accent.opacity(0.12),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: CipherTheme.spacingXL) {
                Spacer()

                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 72, weight: .medium))
                    .foregroundStyle(CipherTheme.accent)
                    .symbolRenderingMode(.hierarchical)
                    .padding(28)
                    .cipherGlass(in: Circle())

                VStack(spacing: CipherTheme.spacingM) {
                    Text("Cipher")
                        .font(.system(size: 48, weight: .bold, design: .rounded))
                    Text("Private chats for your circle — invite only.")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, CipherTheme.spacingXL)
                }

                Spacer()

                PrimaryGlassButton(title: "Get Started", systemImage: "arrow.right") {
                    onContinue()
                }
                .padding(.horizontal, CipherTheme.spacingXL)
                .padding(.bottom, CipherTheme.spacingXL)
            }
        }
    }
}

struct PrivacyCarouselView: View {
    var onContinue: () -> Void
    @State private var page = 0

    // Keep private-key custody distinct from public-key publication. Cipher publishes the
    // public identity key and PQXDH prekeys to the relay so peers can establish sessions;
    // only the private halves remain on-device. The relay also sees routing metadata, so
    // "only ciphertext" would be false even though it cannot decrypt message content.
    //
    // The middle page also claimed the Secure Enclave. It is not, and it will not be: a
    // libsignal identity key is an exportable software key held in the data-protection
    // Keychain. Claiming SE for it is specifically forbidden (plan P10.S05), because the
    // Enclave implies hardware non-extractability this key does not have.
    private var pages: [(String, String, String)] {
        [
            ("lock.fill", String(localized: "Designed for end-to-end encryption"), String(localized: "Built so that only you and the people you chat with can read messages, and Cipher never holds your decryption keys.")),
            ("key.fill", String(localized: "Private keys remain on this iPhone"), String(localized: "Your private identity key is generated on this iPhone and stored in the iOS Keychain so it never syncs to iCloud or appears in a backup.")),
            ("server.rack", String(localized: "The relay cannot decrypt messages"), String(localized: "The relay receives public keys needed to establish encrypted sessions, but never private keys or plaintext. It deletes ciphertext after your device confirms delivery.")),
        ]
    }

    var body: some View {
        VStack(spacing: CipherTheme.spacingL) {
            TabView(selection: $page) {
                ForEach(Array(pages.enumerated()), id: \.offset) { index, item in
                    VStack(spacing: CipherTheme.spacingXL) {
                        Image(systemName: item.0)
                            .font(.system(size: 56, weight: .medium))
                            .foregroundStyle(CipherTheme.accent)
                            .frame(width: 120, height: 120)
                            .cipherGlass(in: Circle())
                        Text(item.1)
                            .font(.title.bold())
                            .multilineTextAlignment(.center)
                        Text(item.2)
                            .font(.body)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, CipherTheme.spacingXL)
                    }
                    .padding()
                    .tag(index)
                }
            }
            .tabViewStyle(.page(indexDisplayMode: .always))

            PrimaryGlassButton(title: page < pages.count - 1 ? "Continue" : "Next") {
                if page < pages.count - 1 {
                    withAnimation { page += 1 }
                } else {
                    onContinue()
                }
            }
            .padding(.horizontal, CipherTheme.spacingXL)
            .padding(.bottom, CipherTheme.spacingXL)
        }
        .navigationTitle("Privacy")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#if DEBUG
#Preview {
    OnboardingFlowView()
        .environment(AppSession())
        .environment(ConversationStore.preview())
}
#endif
