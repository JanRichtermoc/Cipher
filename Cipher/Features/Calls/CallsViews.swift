//
//  CallsViews.swift
//  Cipher
//

import SwiftUI

// Calls do not exist. There is no signalling, no media transport, and nothing in `Envelope` that
// could carry either — so every screen in this file depicts a capability the build does not have,
// and until P5.S10 the list was populated with fabricated call history. The whole file is
// DEBUG-only on the same grounds as group creation (AUDIT 5.5). Note that the fence is not the
// only thing holding it back: the fixtures it renders are DEBUG-only too, so un-fencing this
// file does not compile in Release rather than shipping a fake call log.
#if DEBUG

struct CallsListView: View {
    @Environment(ConversationStore.self) private var store
    @State private var activeCall: ActiveCallPresentation?
    @State private var showIncomingDemo = false

    private var calls: [CallRecord] { store.previewCalls }

    var body: some View {
        NavigationStack {
            Group {
                if calls.isEmpty {
                    EmptyStateView(
                        systemImage: "phone",
                        title: "No Recent Calls",
                        message: "Audio and video calls with Cipher contacts will appear here."
                    )
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(Array(calls.enumerated()), id: \.element.id) { index, call in
                                Button {
                                    if let contact = store.contact(id: call.contactID) {
                                        activeCall = ActiveCallPresentation(contact: contact, kind: call.kind, mode: .outgoing)
                                    }
                                } label: {
                                    CallRowView(call: call)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.horizontal, 16)
                                        .padding(.vertical, 10)
                                        .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                if index < calls.count - 1 {
                                    Divider()
                                        .padding(.leading, 16 + CipherTheme.avatarM + CipherTheme.spacingM)
                                }
                            }
                        }
                        .padding(.top, 4)
                    }
                }
            }
            .navigationTitle("Calls")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showIncomingDemo = true
                    } label: {
                        Image(systemName: "phone.badge.waveform")
                    }
                    .accessibilityLabel("Simulate incoming call")
                }
            }
            .fullScreenCover(item: $activeCall) { presentation in
                ActiveCallView(
                    contact: presentation.contact,
                    kind: presentation.kind,
                    mode: presentation.mode
                ) {
                    activeCall = nil
                }
            }
            .fullScreenCover(isPresented: $showIncomingDemo) {
                if let contact = store.contacts.first {
                    IncomingCallView(contact: contact) { accepted in
                        showIncomingDemo = false
                        if accepted {
                            activeCall = ActiveCallPresentation(contact: contact, kind: .audio, mode: .incoming)
                        }
                    }
                }
            }
        }
    }
}

struct CallRowView: View {
    let call: CallRecord

    var body: some View {
        HStack(spacing: CipherTheme.spacingM) {
            AvatarView(
                initials: call.initials,
                color: call.accentColor,
                size: CipherTheme.avatarM
            )

            VStack(alignment: .leading, spacing: 4) {
                Text(call.contactName)
                    .font(.headline)
                    .foregroundStyle(call.direction == .missed ? CipherTheme.danger : .primary)
                HStack(spacing: 6) {
                    Image(systemName: directionIcon)
                        .foregroundStyle(call.direction == .missed ? CipherTheme.danger : .secondary)
                    Text(directionLabel)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    if let duration = call.durationSeconds {
                        Text("· \(CipherDateFormatting.callDuration(duration))")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 6) {
                Text(CipherDateFormatting.chatList(call.date))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Image(systemName: call.kind == .video ? "video.fill" : "phone.fill")
                    .foregroundStyle(CipherTheme.accent)
            }
        }
        .padding(.vertical, 4)
    }

    private var directionIcon: String {
        switch call.direction {
        case .incoming: return "arrow.down.left"
        case .outgoing: return "arrow.up.right"
        case .missed: return "phone.down"
        }
    }

    private var directionLabel: String {
        switch call.direction {
        case .incoming: String(localized: "Incoming")
        case .outgoing: String(localized: "Outgoing")
        case .missed: String(localized: "Missed")
        }
    }
}

struct ActiveCallPresentation: Identifiable {
    let id = UUID()
    let contact: Contact
    let kind: CallRecord.CallKind
    let mode: CallMode
}

enum CallMode {
    case incoming
    case outgoing
}

struct ActiveCallView: View {
    let contact: Contact
    let kind: CallRecord.CallKind
    var mode: CallMode = .outgoing
    var onEnd: () -> Void

    @State private var startedAt = Date()
    @State private var muted = false
    @State private var speaker = false

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [contact.accentColor.opacity(0.55), Color.black],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: CipherTheme.spacingXL) {
                Spacer()
                AvatarView(
                    initials: contact.initials,
                    color: contact.accentColor,
                    size: 120
                )
                Text(contact.name)
                    .font(.largeTitle.bold())
                    .foregroundStyle(.white)
                Text(kind == .video ? "Cipher Video" : "Cipher Audio")
                    .foregroundStyle(.white.opacity(0.7))
                TimelineView(.periodic(from: startedAt, by: 1)) { context in
                    let elapsed = Int(context.date.timeIntervalSince(startedAt))
                    Text(CipherDateFormatting.elapsedClock(max(0, elapsed)))
                        .font(.title3.monospacedDigit())
                        .foregroundStyle(.white.opacity(0.85))
                }

                Spacer()

                GlassEffectContainer {
                    HStack(spacing: 28) {
                        callControl(muted ? "mic.slash.fill" : "mic.fill", label: String(localized: "Mute")) {
                            muted.toggle()
                        }
                        callControl(speaker ? "speaker.wave.2.fill" : "speaker.fill", label: String(localized: "Speaker")) {
                            speaker.toggle()
                        }
                        if kind == .video {
                            callControl("arrow.triangle.2.circlepath.camera", label: String(localized: "Flip")) {}
                        }
                        Button {
                            onEnd()
                        } label: {
                            Image(systemName: "phone.down.fill")
                                .font(.title2)
                                .foregroundStyle(.white)
                                .frame(width: 68, height: 68)
                                .background(CipherTheme.danger, in: Circle())
                        }
                        .accessibilityLabel("End call")
                    }
                }
                .padding(.bottom, 48)
            }
        }
        .onAppear { startedAt = Date() }
    }

    private func callControl(_ systemName: String, label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.title2)
                .foregroundStyle(.white)
                .frame(width: 60, height: 60)
        }
        .buttonStyle(.glass)
        .accessibilityLabel(label)
    }
}

struct IncomingCallView: View {
    let contact: Contact
    var onFinish: (Bool) -> Void

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [contact.accentColor.opacity(0.6), Color.black.opacity(0.9)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: CipherTheme.spacingXL) {
                Spacer()
                Text("Cipher Audio")
                    .foregroundStyle(.white.opacity(0.7))
                AvatarView(initials: contact.initials, color: contact.accentColor, size: 120)
                Text(contact.name)
                    .font(.largeTitle.bold())
                    .foregroundStyle(.white)
                Text("Incoming call")
                    .foregroundStyle(.white.opacity(0.75))
                Spacer()

                HStack(spacing: 64) {
                    Button {
                        onFinish(false)
                    } label: {
                        VStack {
                            Image(systemName: "phone.down.fill")
                                .font(.title)
                                .foregroundStyle(.white)
                                .frame(width: 72, height: 72)
                                .background(CipherTheme.danger, in: Circle())
                            Text("Decline").foregroundStyle(.white).font(.caption)
                        }
                    }

                    Button {
                        onFinish(true)
                    } label: {
                        VStack {
                            Image(systemName: "phone.fill")
                                .font(.title)
                                .foregroundStyle(.white)
                                .frame(width: 72, height: 72)
                                .background(CipherTheme.success, in: Circle())
                            Text("Accept").foregroundStyle(.white).font(.caption)
                        }
                    }
                }
                .padding(.bottom, 56)
            }
        }
    }
}

#endif

#if DEBUG
#Preview {
    CallsListView()
        .environment(ConversationStore.preview())
}
#endif
