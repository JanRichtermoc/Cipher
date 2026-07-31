//
//  AuthFlowView.swift
//  Cipher
//

import CipherCrypto
import SwiftUI

struct AuthFlowView: View {
    @Environment(AppSession.self) private var session

    var body: some View {
        NavigationStack {
            InviteCodeView()
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
}

struct InviteCodeView: View {
    @State private var code = ""
    @State private var isRedeeming = false
    @State private var errorMessage: String?

    @Environment(AppSession.self) private var session
    @Environment(ConversationStore.self) private var store

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
            // The store owns the engine: two `CryptoEngine.open()` calls would each build their
            // own record store over the same container and the same Keychain key, with no
            // coordination between them — the shape of a lost write.
            let engine = try await store.engine()
            let redeemed = try await InviteRedemption().redeem(code: code, using: engine)
            // Persist the account-bound pending state before the view changes.
            // RootView owns the recoverable adoption/publication pass.
            try session.beginRegistration(with: redeemed.credential)
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

    @State private var name = ""
    @State private var username = ""
    @State private var failure: String?

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
            if let failure {
                Section { Text(failure).foregroundStyle(.red) }
            }
        }
        .safeAreaInset(edge: .bottom) {
            PrimaryGlassButton(
                title: "Enter Cipher",
                systemImage: "checkmark",
                isEnabled: !name.trimmingCharacters(in: .whitespaces).isEmpty &&
                    session.isProfileStorageReady
            ) {
                Task { await finish() }
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

    private func finish() async {
        let resolvedUsername = username.isEmpty
            ? name.lowercased().replacingOccurrences(of: " ", with: "")
            : username
        do {
            try await session.completeProfileSetup(displayName: name, username: resolvedUsername)
            failure = nil
        } catch {
            failure = String(localized: "Could not securely save your profile. Try again.")
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

struct RegistrationRecoveryView: View {
    @Environment(AppSession.self) private var session
    @Environment(ConversationStore.self) private var store
    @State private var failure: String?
    @State private var isWorking = false

    var body: some View {
        lifecycleScreen(
            title: "Finishing secure setup",
            detail: failure ?? "Binding this device to your new Cipher account.",
            action: failure == nil ? nil : "Try Again") {
                Task { await finish() }
            }
            .task { await finish() }
    }

    private func finish() async {
        guard !isWorking, session.destination == .registration else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await store.register()
            try session.completeRegistration()
            failure = nil
        } catch {
            failure = String(localized: "Setup could not finish. Check your connection and try again.")
        }
    }
}

struct AccountCleanupView: View {
    @Environment(AppSession.self) private var session
    @Environment(ConversationStore.self) private var store
    @State private var failure: String?
    @State private var isWorking = false

    var body: some View {
        lifecycleScreen(
            title: "Securing this device",
            detail: failure ?? "Removing the previous account and its encrypted local history.",
            action: failure == nil ? nil : "Try Again") {
                Task { await clean() }
            }
            .task { await clean() }
    }

    private func clean() async {
        guard !isWorking, session.destination == .accountCleanup else { return }
        isWorking = true
        defer { isWorking = false }

        // A prewarmed process can observe the `WhenUnlocked` item before its
        // value is available. Re-read now that the cleanup screen is visible;
        // never erase a valid account merely because launch happened early.
        if session.recoverReadableCredentialBeforeCleanup() {
            failure = nil
            return
        }

        await SessionLifecycle().revokeBestEffort(session.credential)
        do {
            try await store.destroyAccountState()
            try session.completeAccountCleanup()
            failure = nil
        } catch {
            failure = String(localized: "Cipher could not finish removing local account data. Try again.")
        }
    }
}

private func lifecycleScreen(
    title: String, detail: String, action: String?, perform: @escaping () -> Void
) -> some View {
    VStack(spacing: CipherTheme.spacingXL) {
        Spacer()
        ProgressView()
            .controlSize(.large)
        Text(title).font(.title2.bold())
        Text(detail)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.horizontal, CipherTheme.spacingXL)
        Spacer()
        if let action {
            PrimaryGlassButton(
                title: LocalizedStringKey(action), systemImage: "arrow.clockwise", action: perform)
                .padding()
        }
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

#if DEBUG
#Preview("Auth") {
    AuthFlowView()
        .environment(AppSession())
        .environment(ConversationStore.preview())
}

#Preview("Lock") {
    AppLockView()
        .environment(AppSession())
}
#endif
