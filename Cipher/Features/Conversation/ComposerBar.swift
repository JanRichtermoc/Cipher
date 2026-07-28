//
//  ComposerBar.swift
//  Cipher
//

import SwiftUI

struct ComposerBar: View {
    @Binding var text: String
    var replyPreview: String?
    var onClearReply: () -> Void
    var onSend: () -> Void
    var onAttach: () -> Void

    @State private var isRecording = false
    @Namespace private var glassNamespace

    var body: some View {
        VStack(spacing: 10) {
            if let replyPreview {
                HStack {
                    Label(replyPreview, systemImage: "arrowshape.turn.up.left")
                        .font(.caption)
                        .lineLimit(1)
                        .foregroundStyle(.primary)
                    Spacer(minLength: 8)
                    Button(action: onClearReply) {
                        Image(systemName: "xmark.circle.fill")
                            .symbolRenderingMode(.hierarchical)
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .padding(.horizontal, CipherTheme.spacingM)
            }

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

            GlassEffectContainer(spacing: 20) {
                HStack(alignment: .bottom, spacing: 12) {
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
