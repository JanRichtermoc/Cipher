//
//  ComposerBar.swift
//  Cipher
//

import SwiftUI

struct ComposerBar: View {
    @Binding var text: String
    var onSend: () -> Void
    var onAttach: () -> Void

    #if DEBUG
    @State private var isRecording = false
    #endif
    @Namespace private var glassNamespace

    var body: some View {
        VStack(spacing: 10) {
            // Voice messages, like attachments, have no client path and no payload type. The
            // recording affordance was a button with an empty action next to an animated
            // "Recording…" line — the most convincing kind of control that does nothing — so it
            // and the indicator are DEBUG-only until there is something to record into.
            #if DEBUG
            if isRecording {
                HStack {
                    Image(systemName: "waveform")
                        .foregroundStyle(CipherTheme.danger)
                        .symbolEffect(.variableColor.iterative)
                    Text("Recording… release to cancel")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .padding(.horizontal, CipherTheme.spacingM)
            }
            #endif

            GlassEffectContainer(spacing: 20) {
                HStack(alignment: .bottom, spacing: 12) {
                    // Real since P6.S04: it opens the photo picker, and what comes back is
                    // encrypted before it is uploaded. It was DEBUG-only while it opened a
                    // sheet of five sources that all dismissed and did nothing.
                    Button(action: onAttach) {
                        Image(systemName: "plus")
                            .font(.body.weight(.semibold))
                            .foregroundStyle(.primary)
                            .frame(width: 46, height: 46)
                            .contentShape(Circle())
                    }
                    .buttonStyle(.plain)
                    .glassEffect(.regular.interactive(), in: Circle())
                    .glassEffectID("composerAttach", in: glassNamespace)
                    .accessibilityLabel("Attach")

                    TextField("Message", text: $text, axis: .vertical)
                        .textFieldStyle(.plain)
                        .lineLimit(1...6)
                        .padding(.horizontal, 18)
                        .padding(.vertical, 12)
                        .frame(maxWidth: .infinity, minHeight: 46, alignment: .leading)
                        .glassEffect(.regular.interactive(), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
                        .glassEffectID("composerField", in: glassNamespace)

                    if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        #if DEBUG
                        Button {} label: {
                            Image(systemName: "mic.fill")
                                .font(.body.weight(.semibold))
                                .foregroundStyle(.primary)
                                .frame(width: 46, height: 46)
                                .contentShape(Circle())
                        }
                        .buttonStyle(.plain)
                        .glassEffect(.regular.interactive(), in: Circle())
                        .simultaneousGesture(
                            DragGesture(minimumDistance: 0)
                                .onChanged { _ in isRecording = true }
                                .onEnded { _ in isRecording = false }
                        )
                        .glassEffectID("composerAction", in: glassNamespace)
                        .accessibilityLabel("Hold to record")
                        #endif
                    } else {
                        Button(action: onSend) {
                            Image(systemName: "arrow.up")
                                .font(.body.weight(.bold))
                                .foregroundStyle(.white)
                                .frame(width: 46, height: 46)
                                .contentShape(Circle())
                        }
                        .buttonStyle(.plain)
                        .glassEffect(.regular.tint(CipherTheme.accent).interactive(), in: Circle())
                        .glassEffectID("composerAction", in: glassNamespace)
                        .accessibilityLabel("Send")
                    }
                }
            }
            .padding(.horizontal, CipherTheme.spacingM)
            .padding(.bottom, 10)
            .safeAreaPadding(.bottom, 8)
        }
        .padding(.top, 6)
        .tint(.primary)
    }
}
