//
//  SettingsViews.swift
//  Cipher
//

import SwiftUI

struct SettingsHubView: View {
    @Environment(AppSession.self) private var session
    @Environment(ConversationStore.self) private var store

    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink {
                        EditProfileView()
                    } label: {
                        HStack(spacing: CipherTheme.spacingM) {
                            AvatarView(
                                initials: profileInitials,
                                color: CipherTheme.accent,
                                size: CipherTheme.avatarL
                            )
                            VStack(alignment: .leading, spacing: 4) {
                                Text(session.displayName)
                                    .font(.title3.bold())
                                Text("@\(session.username)")
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }

                if let aci = store.localAci {
                    Section {
                        LabeledContent("Your Cipher ID") {
                            Text(aci.uuidString.lowercased())
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                        }
                        Button("Copy Cipher ID", systemImage: "doc.on.doc") {
                            SecurePasteboard.copy(aci.uuidString.lowercased())
                        }
                    } footer: {
                        Text("Give this to someone so they can message you. It is the only identifier Cipher has — there is no phone number, email, or searchable username.")
                    }
                }

                Section {
                    // The relay can issue invites, but the client has no authenticated issuance
                    // call yet. Do not expose a stub that fabricates codes or performs no action;
                    // restore this entry only with the real server-backed flow (AUDIT 5.30).
                    NavigationLink {
                        LinkedDevicesView()
                    } label: {
                        SettingsRow(title: "Linked Devices", systemImage: "laptopcomputer.and.iphone", tint: .indigo)
                    }
                    // Push, permission requests and local preview rendering do not exist until
                    // P7/P8. Keep notification controls out of Release until they have a mechanism
                    // to configure; a disabled form still advertises a product surface (AUDIT 5.30).
                    NavigationLink {
                        PrivacySecurityView()
                    } label: {
                        SettingsRow(title: "Privacy & Security", systemImage: "lock.shield.fill", tint: .green)
                    }
                }

                Section {
                    NavigationLink {
                        HelpView()
                    } label: {
                        SettingsRow(title: "Help", systemImage: "questionmark.circle.fill", tint: .teal)
                    }
                    NavigationLink {
                        AboutView()
                    } label: {
                        SettingsRow(title: "About", systemImage: "info.circle.fill", tint: .gray)
                    }
                    #if DEBUG
                    NavigationLink {
                        UICatalogView()
                    } label: {
                        SettingsRow(title: "UI Catalog", systemImage: "square.grid.2x2.fill", tint: .purple)
                    }
                    #endif
                }

                // Development only. This sat outside the #endif above, so a shipping build
                // offered users a destructive "Demo" reset that wiped the authentication
                // state. Real account deletion is a separate, server-backed control (P6.S05).
                #if DEBUG
                Section {
                    Button(role: .destructive) {
                        session.resetDemoState()
                    } label: {
                        Label("Leave & Reset Demo", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                }
                #endif
            }
            .contentMargins(.bottom, 28, for: .scrollContent)
            .navigationTitle("Settings")
        }
    }

    private var profileInitials: String {
        let parts = session.displayName.split(separator: " ")
        if parts.count >= 2 {
            return String(parts[0].prefix(1) + parts[1].prefix(1)).uppercased()
        }
        return String(session.displayName.prefix(2)).uppercased()
    }
}

struct EditProfileView: View {
    @Environment(AppSession.self) private var session
    @State private var name = ""
    @State private var username = ""

    var body: some View {
        Form {
            Section {
                // Initials are the only supported avatar. The former photo control had no
                // picker, storage or delivery path and therefore performed no action.
                HStack {
                    Spacer()
                    AvatarView(initials: String(name.prefix(2)).uppercased(), color: CipherTheme.accent, size: CipherTheme.avatarXL)
                    Spacer()
                }
                .listRowBackground(Color.clear)
            }
            Section {
                TextField("Name", text: $name)
                TextField("Username", text: $username)
                    .textInputAutocapitalization(.never)
            } footer: {
                Text("No email or phone — just a name your friends recognize.")
            }
        }
        .navigationTitle("Edit Profile")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") {
                    session.displayName = name
                    session.username = username
                }
            }
        }
        .onAppear {
            name = session.displayName
            username = session.username
        }
    }
}

/// One device, because that is a locked protocol decision rather than a missing feature.
///
/// This screen used to list an iPad and a MacBook with plausible "last active" times and a Revoke
/// button, above a footer admitting it was UI only. `Envelope` has no `deviceId` field at all
/// (plan §0.2.5): a second device is a `wireVersion` 2 change, so there is nothing to list and
/// nothing to revoke. Saying so is the whole screen.
struct LinkedDevicesView: View {
    var body: some View {
        List {
            Section {
                HStack {
                    Image(systemName: "iphone")
                        .foregroundStyle(CipherTheme.accent)
                        .frame(width: 28)
                    Text("This iPhone")
                    Spacer()
                    Text("This device")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } footer: {
                Text("Cipher is single-device by design. The message format carries no device identifier, so a second device cannot be linked and there is nothing here to revoke.")
            }
        }
        .navigationTitle("Linked Devices")
    }
}

struct PrivacySecurityView: View {
    @Environment(AppSession.self) private var session
    @Environment(ConversationStore.self) private var store

    var body: some View {
        @Bindable var session = session
        Form {
            // Real since P3.S02: unlocking requires a successful device-owner check, and
            // the app re-locks on every move out of the foreground. Before that this said
            // "Require Face ID" while asking for nothing, and the lock engaged only on a
            // cold launch — backgrounding and returning left it open (C-03, AUDIT 5.8).
            Section("App Lock") {
                Toggle("Lock Cipher", isOn: $session.appLockEnabled)
                    .disabled(!session.canUseAppLock)

                if session.canUseAppLock {
                    Text("Require Face ID or your device passcode to reopen Cipher.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    // Offering a lock the device cannot enforce is the deceptive-UI case
                    // P1.S05 was about, so the control is disabled and says why.
                    Text("Set a device passcode to use the app lock.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                if session.appLockEnabled {
                    Button("Lock Now") { session.lockIfNeeded() }
                }
            }

            // Blocking is local and real: `MessageRepository` refuses to send to a blocked peer,
            // and an incoming message from one is decrypted (the ratchet must advance or the
            // session desynchronises), then discarded and acknowledged.
            Section("Blocked") {
                if store.blockedContactIDs.isEmpty {
                    Text("No blocked contacts")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(store.contacts.filter { store.blockedContactIDs.contains($0.id) }) { contact in
                        HStack {
                            Text(contact.name)
                            Spacer()
                            Button("Unblock") { Task { await store.toggleBlock(contact.id) } }
                        }
                    }
                }
            }
        }
        .navigationTitle("Privacy & Security")
    }
}

struct HelpView: View {
    var body: some View {
        List {
            NavigationLink("How encryption works") {
                // Public identity and prekey material is published to the relay. Only the
                // private halves stay local; collapsing both into "keys" is a false claim.
                Text("Cipher uses the Signal Protocol. Your device retains all private key material. The server receives public keys needed to establish encrypted sessions and relays ciphertext it cannot decrypt.")
                    .padding()
            }
            Link(destination: URL(string: "https://developer.apple.com/design/resources/")!) {
                Label("Apple Design Resources", systemImage: "safari")
            }
        }
        .navigationTitle("Help")
    }
}

struct AboutView: View {
    var body: some View {
        List {
            Section {
                LabeledContent("Version", value: Self.version)
                LabeledContent("Build", value: Self.build)
            }
            Section {
                Text("Cipher keeps encryption and decryption on your device. The server relays ciphertext it cannot read and deletes each message as soon as your device confirms it arrived.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Section {
                NavigationLink {
                    AcknowledgementsView()
                } label: {
                    SettingsRow(title: "Acknowledgements", systemImage: "doc.text.fill", tint: .gray)
                }
            } footer: {
                Text("Cipher is built on open-source software.")
            }
        }
        .navigationTitle("About")
    }

    /// Read from the bundle rather than written here. The previous values — "1.0 (UI)" and
    /// "UI-only shell" — were accurate when nothing worked and would have become a lie the
    /// moment they stopped being updated by hand.
    private static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
    }

    private static var build: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
    }
}

/// The third-party licences Cipher is obliged to surface (P8.S07, AUDIT 6.2).
///
/// libsignal is AGPL-3.0, and obligation 3 in `NOTICE.md` is to show its
/// acknowledgements here. This is the discharge of a licence term, not a nicety, so
/// the text is rendered rather than summarised and the licence is shown in full.
///
/// ## The content is CocoaPods', not ours
///
/// `Acknowledgements.plist` is a byte-identical copy of what CocoaPods generates into
/// `Pods/Target Support Files/`, which is outside the app bundle and therefore
/// unreadable at runtime. `Scripts/verify-acknowledgements.sh` fails when the two
/// stop matching, so a dependency bump that changes a licence cannot leave the
/// previous one on this screen — the copy is kept honest by a gate rather than by
/// somebody remembering.
struct AcknowledgementsView: View {

    private let libraries = Acknowledgement.load()

    var body: some View {
        List {
            if libraries.isEmpty {
                // Never silently empty. An acknowledgements screen that renders
                // nothing looks identical to one that has nothing to acknowledge,
                // and the difference is a licence violation.
                Section {
                    Text("Acknowledgements are unavailable in this build.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            ForEach(libraries) { library in
                Section(library.name) {
                    Text(library.licence)
                        .font(.caption2.monospaced())
                        .textSelection(.enabled)
                }
            }
        }
        .navigationTitle("Acknowledgements")
    }
}

/// One library and its licence, as read from the bundled plist.
///
/// `nonisolated` deliberately: this file's default isolation is the main actor, and reading a
/// bundle resource has nothing to do with the main actor. Leaving it inferred would mean the
/// licence text could only be examined from the main actor — including by a test, which is the
/// only thing that checks the obligation is met at all.
nonisolated struct Acknowledgement: Identifiable, Sendable {
    let name: String
    let licence: String
    var id: String { name }

    /// Reads the plist CocoaPods generated.
    ///
    /// The header and footer entries CocoaPods adds are dropped: the first is a
    /// sentence introducing the list, the last is its own attribution, and neither is
    /// a library. Everything else is kept exactly as generated — an entry this code
    /// did not recognise would be one whose licence went unshown.
    static func load() -> [Acknowledgement] {
        guard let url = Bundle.main.url(forResource: "Acknowledgements", withExtension: "plist"),
              let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil) as? [String: Any],
              let entries = plist["PreferenceSpecifiers"] as? [[String: Any]]
        else {
            return []
        }

        return entries.compactMap { entry in
            guard let name = entry["Title"] as? String, !name.isEmpty,
                  name != "Acknowledgements",
                  let licence = entry["FooterText"] as? String, !licence.isEmpty
            else {
                return nil
            }
            return Acknowledgement(name: name, licence: licence)
        }
    }
}

#if DEBUG
#Preview {
    SettingsHubView()
        .environment(AppSession())
        .environment(ConversationStore.preview())
}
#endif
