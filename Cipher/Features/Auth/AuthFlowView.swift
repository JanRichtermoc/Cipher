//
//  AuthFlowView.swift
//  Cipher
//

import SwiftUI

struct AuthFlowView: View {
    @Environment(AppSession.self) private var session
    @State private var path = NavigationPath()

    var body: some View {
        NavigationStack(path: $path) {
            InviteCodeView {
                path.append(AuthRoute.profileSetup)
            }
            .navigationDestination(for: AuthRoute.self) { route in
                switch route {
                case .profileSetup:
                    ProfileSetupView {
                        #if DEBUG
                        try? session.signInForDevelopment()
                        #endif
                    }
                }
            }
            .toolbar {
                #if DEBUG
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Skip") {
                        session.debugSkipToMain = true
                        try? session.signInForDevelopment()
                        session.isAppLocked = false
                    }
                }
                #endif
            }
        }
    }

    enum AuthRoute: Hashable {
        case profileSetup
    }
}

struct InviteCodeView: View {
    var onContinue: () -> Void
    @State private var code = ""

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    CipherTheme.accentDeep.opacity(0.2),
                    Color(.systemBackground),
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: CipherTheme.spacingXL) {
                Spacer()

                Image(systemName: "person.badge.key.fill")
                    .font(.system(size: 56, weight: .medium))
                    .foregroundStyle(CipherTheme.accent)
                    .padding(24)
                    .cipherGlass(in: Circle())

                VStack(spacing: CipherTheme.spacingM) {
                    Text("Join your circle")
                        .font(.largeTitle.bold())
                    Text("Cipher is invite-only for you and your friends. Enter the code someone shared with you.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, CipherTheme.spacingXL)
                }

                TextField("Invite code", text: $code)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .font(.title2.monospaced().weight(.medium))
                    .multilineTextAlignment(.center)
                    .padding()
                    .cipherGlass(in: RoundedRectangle(cornerRadius: CipherTheme.radiusL, style: .continuous))
                    .padding(.horizontal, CipherTheme.spacingXL)

                Spacer()

                PrimaryGlassButton(
                    title: "Continue",
                    systemImage: "arrow.right",
                    isEnabled: code.trimmingCharacters(in: .whitespacesAndNewlines).count >= 4
                ) {
                    onContinue()
                }
                .padding(.horizontal, CipherTheme.spacingXL)
                .padding(.bottom, CipherTheme.spacingXL)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct ProfileSetupView: View {
    @Environment(AppSession.self) private var session
    var onContinue: () -> Void

    @State private var name = ""
    @State private var username = ""

    var body: some View {
        Form {
            Section {
                HStack {
                    Spacer()
                    AvatarView(
                        initials: initials,
                        color: CipherTheme.accent,
                        size: CipherTheme.avatarXL
                    )
                    Spacer()
                }
                .listRowBackground(Color.clear)

                Button("Choose Photo") {}
                    .frame(maxWidth: .infinity)
            }

            Section {
                TextField("Your name", text: $name)
                TextField("Username", text: $username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            } footer: {
                Text("Friends will see this name in chats. No email or phone number needed.")
            }
        }
        .safeAreaInset(edge: .bottom) {
            PrimaryGlassButton(
                title: "Enter Cipher",
                systemImage: "checkmark",
                isEnabled: !name.trimmingCharacters(in: .whitespaces).isEmpty
            ) {
                session.displayName = name
                session.username = username.isEmpty
                    ? name.lowercased().replacingOccurrences(of: " ", with: "")
                    : username
                onContinue()
            }
            .padding()
        }
        .navigationTitle("Who are you?")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if name.isEmpty { name = session.displayName == "You" ? "" : session.displayName }
            if username.isEmpty { username = session.username == "you" ? "" : session.username }
        }
    }

    private var initials: String {
        let parts = name.split(separator: " ")
        if parts.count >= 2 {
            return String(parts[0].prefix(1) + parts[1].prefix(1)).uppercased()
        }
        return String(name.prefix(2)).uppercased().nilIfEmpty ?? "YO"
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

struct AppLockView: View {
    @Environment(AppSession.self) private var session

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(.systemBackground), CipherTheme.accentDeep.opacity(0.25)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: CipherTheme.spacingXL) {
                Spacer()
                Image(systemName: "lock.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(CipherTheme.accent)
                    .padding(24)
                    .cipherGlass(in: Circle())

                Text("Cipher is Locked")
                    .font(.title.bold())

                // This screen promised "Unlock with Face ID or your device passcode" while
                // both buttons called `unlock()` directly — no LocalAuthentication, no
                // failure path. The promise is removed rather than the screen: it still
                // hides content from a casual glance, which is all it ever did.
                // P3.S02 makes it real and restores the biometric copy.
                UnimplementedNotice(
                    "This screen does not ask for Face ID or your passcode yet. It hides your chats from view; it does not keep anyone out."
                )
                .padding(.horizontal, CipherTheme.spacingXL)

                Spacer()

                PrimaryGlassButton(title: "Continue", systemImage: "lock.open") {
                    session.unlock()
                }
                .padding(.horizontal, CipherTheme.spacingXL)
                .padding(.bottom, CipherTheme.spacingXL)
            }
        }
    }
}

#Preview("Auth") {
    AuthFlowView()
        .environment(AppSession())
}

#Preview("Lock") {
    AppLockView()
        .environment(AppSession())
}
