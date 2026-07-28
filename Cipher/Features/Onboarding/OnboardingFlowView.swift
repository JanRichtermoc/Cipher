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
        case permissions
    }

    var body: some View {
        NavigationStack {
            Group {
                switch step {
                case .welcome:
                    WelcomeView(onContinue: { step = .privacy })
                case .privacy:
                    PrivacyCarouselView(onContinue: { step = .permissions })
                case .permissions:
                    PermissionsView(onContinue: {
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

    // These three pillars are Cipher's design, and they are stated as design — not as
    // things that already work. The previous copy asserted all three in the present tense
    // on the first screen a user ever sees, while the app has no encryption in its
    // messaging path and no relay at all.
    //
    // The middle page also claimed the Secure Enclave. It is not, and it will not be: a
    // libsignal identity key is an exportable software key held in the data-protection
    // Keychain. Claiming SE for it is specifically forbidden (plan P10.S05), because the
    // Enclave implies hardware non-extractability this key does not have.
    private var pages: [(String, String, String)] {
        [
            ("lock.fill", String(localized: "Designed for end-to-end encryption"), String(localized: "Built so that only you and the people you chat with can read messages, and Cipher never holds your decryption keys.")),
            ("key.fill", String(localized: "Keys stay on your device"), String(localized: "Your identity key is generated on your iPhone and stored in the iOS Keychain, marked so it never syncs to iCloud and never appears in a backup.")),
            ("server.rack", String(localized: "The relay only sees ciphertext"), String(localized: "The server is designed to forward encrypted blobs and delete them once delivered — never plaintext, never your keys.")),
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

            // The pillars above describe the destination. This says where the build
            // actually is, on the same screen, so no one reads them as a promise already
            // kept. Removed by P5.S14, when messaging genuinely runs through CryptoEngine.
            UnimplementedNotice(
                "Preview build: messages are not encrypted yet and are not sent anywhere. Do not use Cipher for anything you need kept private."
            )
            .padding(.horizontal, CipherTheme.spacingXL)

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

struct PermissionsView: View {
    var onContinue: () -> Void
    @State private var notificationsOn = true

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $notificationsOn) {
                    Label("Notifications", systemImage: "bell.badge.fill")
                }
            } footer: {
                Text("So you know when a friend messages you. Cipher never puts message text in the notification payload.")
            }
        }
        .safeAreaInset(edge: .bottom) {
            PrimaryGlassButton(title: "Continue", systemImage: "checkmark") {
                onContinue()
            }
            .padding()
        }
        .navigationTitle("Notifications")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    OnboardingFlowView()
        .environment(AppSession())
        .environment(MockStore())
}
