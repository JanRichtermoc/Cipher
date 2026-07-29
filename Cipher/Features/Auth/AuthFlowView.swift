//
//  AuthFlowView.swift
//  Cipher
//

import CipherCrypto
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
                        session.debugUnlockWithoutAuthentication()
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
    @State private var isRedeeming = false
    @State private var errorMessage: String?

    @Environment(AppSession.self) private var session

    /// Whether the button is *offered*, not whether the code is valid.
    ///
    /// AUDIT C-01: this used to be the entire authentication decision — `count >= 4` and you
    /// were in. It is now nothing more than "there is something to send". The code is judged
    /// by the relay, which is the only party that can judge it, and the app becomes
    /// authenticated only when the relay hands back a token.
    private var canSubmit: Bool {
        !isRedeeming && !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

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

                if let errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, CipherTheme.spacingXL)
                }

                PrimaryGlassButton(
                    title: isRedeeming ? "Checking…" : "Continue",
                    systemImage: "arrow.right",
                    isEnabled: canSubmit
                ) {
                    Task { await submit() }
                }
                .padding(.horizontal, CipherTheme.spacingXL)
                .padding(.bottom, CipherTheme.spacingXL)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
    }

    /// Redeem the code against the relay, and sign in only if it issues a session.
    ///
    /// Every failure leaves the app signed out. There is no path here that advances the flow
    /// without a server-issued credential — that is the whole of C-01's fix, and the reason
    /// this is `async` rather than a button that calls `onContinue()`.
    private func submit() async {
        isRedeeming = true
        errorMessage = nil
        defer { isRedeeming = false }

        do {
            let engine = try await CryptoEngine.open()
            let redeemed = try await InviteRedemption().redeem(code: code, using: engine)
            try session.signIn(with: redeemed.credential)
            onContinue()
        } catch let failure as InviteRedemption.Failure {
            // The relay does not distinguish unknown from spent from expired, and neither does
            // this copy — saying "already used" would confirm to a guessing loop that a code
            // had once been real.
            errorMessage = switch failure {
            case .refused:
                String(localized: "That code cannot be used. Ask for a new invite.")
            case .rateLimited:
                String(localized: "Too many attempts. Wait an hour and try again.")
            case .unreachable:
                String(localized: "Could not reach the relay. Check your connection.")
            case .malformedResponse:
                String(localized: "Something went wrong. Try again.")
            }
        } catch {
            errorMessage = String(localized: "Something went wrong. Try again.")
        }
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
    @State private var failure: String?
    @State private var isAuthenticating = false

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

                // Real since P3.S02. It previously promised "Unlock with Face ID or your
                // device passcode" while both buttons called `unlock()` directly — no
                // LocalAuthentication, no failure path (C-03). P1.S05 removed the promise;
                // this restores it now that the check exists.
                Text("Unlock with Face ID or your device passcode.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, CipherTheme.spacingXL)

                if let failure {
                    // Cancel and failure are reported, never swallowed. A dismissed prompt
                    // that silently left the screen unchanged would read as a broken button
                    // and train the user to tap until something happens.
                    Text(failure)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, CipherTheme.spacingXL)
                }

                Spacer()

                PrimaryGlassButton(title: "Unlock", systemImage: "lock.open") {
                    Task { await attemptUnlock() }
                }
                .padding(.horizontal, CipherTheme.spacingXL)
                .padding(.bottom, CipherTheme.spacingXL)
                .disabled(isAuthenticating)
            }
        }
        // Prompt on appear as well as on tap, so returning to a locked app does not need an
        // extra deliberate tap to get to the check the user already expects.
        .task { await attemptUnlock() }
    }

    private func attemptUnlock() async {
        guard !isAuthenticating else { return }
        isAuthenticating = true
        defer { isAuthenticating = false }

        do {
            try await session.unlock(reason: "Unlock Cipher")
            failure = nil
        } catch DeviceAuthenticationError.cancelled {
            failure = nil  // A deliberate dismissal is not an error to shout about.
        } catch DeviceAuthenticationError.unavailable {
            failure = String(localized: "Set a device passcode to use the app lock.")
        } catch {
            failure = String(localized: "Could not verify it is you. Try again.")
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
