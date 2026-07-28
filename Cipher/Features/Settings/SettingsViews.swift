//
//  SettingsViews.swift
//  Cipher
//

import SwiftUI

struct SettingsHubView: View {
    @Environment(AppSession.self) private var session
    @Environment(MockStore.self) private var store

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

                Section {
                    NavigationLink {
                        InviteFriendsView()
                    } label: {
                        SettingsRow(title: "Invite Friends", systemImage: "person.badge.plus", tint: .blue)
                    }
                    NavigationLink {
                        LinkedDevicesView()
                    } label: {
                        SettingsRow(title: "Linked Devices", systemImage: "laptopcomputer.and.iphone", tint: .indigo)
                    }
                    NavigationLink {
                        AppearanceSettingsView()
                    } label: {
                        SettingsRow(title: "Appearance", systemImage: "paintbrush.fill", tint: .pink)
                    }
                    NavigationLink {
                        NotificationSettingsView()
                    } label: {
                        SettingsRow(title: "Notifications", systemImage: "bell.badge.fill", tint: .red)
                    }
                    NavigationLink {
                        ChatsSettingsView()
                    } label: {
                        SettingsRow(title: "Chats", systemImage: "bubble.left.and.bubble.right.fill", tint: CipherTheme.accent)
                    }
                    NavigationLink {
                        PrivacySecurityView()
                    } label: {
                        SettingsRow(title: "Privacy & Security", systemImage: "lock.shield.fill", tint: .green)
                    }
                    NavigationLink {
                        StorageSettingsView()
                    } label: {
                        SettingsRow(title: "Storage", systemImage: "internaldrive.fill", tint: .orange)
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
                HStack {
                    Spacer()
                    AvatarView(initials: String(name.prefix(2)).uppercased(), color: CipherTheme.accent, size: CipherTheme.avatarXL)
                    Spacer()
                }
                .listRowBackground(Color.clear)
                Button("Choose Photo") {}
                    .frame(maxWidth: .infinity)
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

struct InviteFriendsView: View {
    // Fixtures, not invitations. These are constants compiled into every copy of the app:
    // identical for every user, reusable forever, and known to anyone who has the binary.
    // Real codes are server-generated, single-use, expiring and rate-limited (P4.S03), and
    // are redeemed against the server rather than compared on-device (P5.S09).
    #if DEBUG
    private let codes = ["CIPHER-7K2M", "CIPHER-9QPL", "CIPHER-4XAB"]
    #else
    private let codes: [String] = []
    #endif

    var body: some View {
        List {
            Section {
                Text("Cipher is invite-only. No email or phone number is required to join — an identifier we never collect cannot be leaked, correlated, or seized.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .listRowBackground(Color.clear)
            }

            if codes.isEmpty {
                Section {
                    UnimplementedNotice("Invite codes are not implemented yet. They have to be issued by the server so they can be single-use and expiring, and there is no server yet.")
                        .listRowBackground(Color.clear)
                }
            }

            Section("Your invite codes") {
                ForEach(codes, id: \.self) { code in
                    HStack {
                        Text(code)
                            .font(.body.monospaced().weight(.medium))
                        Spacer()
                        Button("Copy") {
                            UIPasteboard.general.string = code
                            UIImpactFeedbackGenerator(style: .light).impactOccurred()
                        }
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(CipherTheme.accent)
                    }
                }
            }

            Section {
                Button("Leave Cipher Circle", role: .destructive) {}
            } footer: {
                Text("Removes this device from the circle. Your friends keep their chats.")
            }
        }
        .navigationTitle("Invite Friends")
    }
}

struct LinkedDevicesView: View {
    @Environment(MockStore.self) private var store

    var body: some View {
        List {
            Section {
                ForEach(store.linkedDevices) { device in
                    HStack {
                        Image(systemName: device.isCurrent ? "iphone" : "laptopcomputer")
                            .foregroundStyle(CipherTheme.accent)
                            .frame(width: 28)
                        VStack(alignment: .leading) {
                            Text(device.name)
                            Text(device.lastActiveLabel)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if device.isCurrent {
                            Text("This device")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            Button("Revoke", role: .destructive) {
                                store.revokeDevice(device.id)
                            }
                            .font(.caption)
                        }
                    }
                }
            } footer: {
                Text("Revoking a device signs it out immediately. UI only — no real sessions.")
            }

            Section {
                Button {
                } label: {
                    Label("Link New Device", systemImage: "qrcode.viewfinder")
                }
            }
        }
        .navigationTitle("Linked Devices")
    }
}

struct AppearanceSettingsView: View {
    @State private var followSystem = true

    var body: some View {
        Form {
            Section {
                Toggle("Match System Appearance", isOn: $followSystem)
            } footer: {
                Text("Cipher uses system Dynamic Type and Liquid Glass materials automatically.")
            }
            Section("Accent") {
                HStack(spacing: 12) {
                    Circle().fill(CipherTheme.accent).frame(width: 28, height: 28)
                        .overlay(Circle().strokeBorder(.primary, lineWidth: 2))
                    Circle().fill(Color.blue).frame(width: 28, height: 28)
                    Circle().fill(Color.orange).frame(width: 28, height: 28)
                    Circle().fill(Color.mint).frame(width: 28, height: 28)
                }
                .padding(.vertical, 4)
            }
        }
        .navigationTitle("Appearance")
    }
}

struct NotificationSettingsView: View {
    @Environment(AppSession.self) private var session
    @State private var sounds = true
    @State private var badges = true

    var body: some View {
        @Bindable var session = session
        Form {
            // The old footer described the intended design in the present tense, which read
            // as a guarantee. There are no notifications at all yet.
            Section {
                Toggle("Show Preview", isOn: $session.notificationPreviewsEnabled)
                Toggle("Sounds", isOn: $sounds)
                Toggle("Badges", isOn: $badges)
            } footer: {
                VStack(alignment: .leading, spacing: 8) {
                    UnimplementedNotice("Cipher does not send notifications yet. None of these settings does anything.")
                    Text("When they arrive, the server payload will carry no message content — previews are rendered on-device, after decryption, and default to off.")
                }
            }
            .disabled(true)
        }
        .navigationTitle("Notifications")
    }
}

struct ChatsSettingsView: View {
    @State private var enterIsSend = false

    var body: some View {
        Form {
            Section {
                Toggle("Enter Key Sends", isOn: $enterIsSend)
                NavigationLink("Archived Chats") {
                    EmptyStateView(systemImage: "archivebox", title: "No Archives", message: "Archived chats will appear here.")
                }
                Button("Export Chat History") {}
            }
        }
        .navigationTitle("Chats")
    }
}

struct PrivacySecurityView: View {
    @Environment(AppSession.self) private var session
    @Environment(MockStore.self) private var store

    var body: some View {
        @Bindable var session = session
        Form {
            // "Require Face ID" claimed biometrics the app never asks for, and the lock only
            // ever engaged on a cold launch — backgrounding and returning left it open. The
            // label now describes what the control actually does. Real biometric auth and
            // re-locking on background arrive together in P3.S02.
            Section("App Lock") {
                Toggle("Lock on launch", isOn: $session.appLockEnabled)
                if session.appLockEnabled {
                    Button("Lock Now") { session.lockIfNeeded() }
                }
                UnimplementedNotice(
                    "This is a privacy screen, not a security control: unlocking does not yet ask for Face ID or your passcode, and the app does not re-lock when you switch away from it."
                )
            }

            Section("Screen Security") {
                Toggle("Screenshot Warning", isOn: $session.screenshotWarningEnabled)
                    .unimplemented("Nothing observes screenshots yet, so this warns you about nothing.")
            }

            Section("Disappearing Messages") {
                Picker("Default Timer", selection: $session.defaultDisappearingSeconds) {
                    Text("Off").tag(0)
                    Text("1 hour").tag(3600)
                    Text("1 day").tag(86_400)
                    Text("1 week").tag(604_800)
                }
                .unimplemented("Messages are not deleted yet. Nothing reads this setting.")
            }

            Section("Blocked") {
                if store.blockedContactIDs.isEmpty {
                    Text("No blocked contacts")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(store.contacts.filter { store.blockedContactIDs.contains($0.id) }) { contact in
                        HStack {
                            Text(contact.name)
                            Spacer()
                            Button("Unblock") { store.toggleBlock(contact.id) }
                        }
                    }
                }
            }

            Section("Identity") {
                NavigationLink("Safety Numbers Explained") {
                    ScrollView {
                        Text("Safety numbers let you verify that the key you see for a contact matches what they see for you. Scan the QR code or compare the digit groups in person.")
                            .padding()
                    }
                    .navigationTitle("Safety Numbers")
                }
                NavigationLink("Registration Lock PIN") {
                    Form {
                        SecureField("PIN", text: .constant(""))
                        Text("UI stub — no PIN is stored.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .navigationTitle("Registration Lock")
                }
            }

            Section("Sessions") {
                NavigationLink("Manage Sessions") {
                    LinkedDevicesView()
                }
            }
        }
        .navigationTitle("Privacy & Security")
        .onChange(of: session.appLockEnabled) { _, enabled in
            if !enabled { session.isAppLocked = false }
        }
    }
}

struct StorageSettingsView: View {
    var body: some View {
        Form {
            Section {
                LabeledContent("Messages", value: "24 MB")
                LabeledContent("Media", value: "180 MB")
                LabeledContent("Other", value: "6 MB")
            }
            Section {
                Button("Manage Storage") {}
                Button("Clear Cache", role: .destructive) {}
            }
        }
        .navigationTitle("Storage")
    }
}

struct HelpView: View {
    var body: some View {
        List {
            NavigationLink("How encryption works") {
                Text("Cipher uses the Signal Protocol. Keys never leave your devices. The server only relays ciphertext.")
                    .padding()
            }
            NavigationLink("Contact support") {
                Text("support@cipher.app (placeholder)")
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
                LabeledContent("Version", value: "1.0 (UI)")
                LabeledContent("Build", value: "UI-only shell")
            }
            Section {
                Text("Cipher keeps encryption and decryption on your device. This build demonstrates the complete messaging interface with Liquid Glass chrome.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("About")
    }
}

#Preview {
    SettingsHubView()
        .environment(AppSession())
        .environment(MockStore())
}
