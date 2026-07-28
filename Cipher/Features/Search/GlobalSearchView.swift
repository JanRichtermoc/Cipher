//
//  GlobalSearchView.swift
//  Cipher
//

import SwiftUI

struct GlobalSearchView: View {
    @Environment(MockStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""

    var onSelectChat: (UUID) -> Void

    var body: some View {
        NavigationStack {
            Group {
                if query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    EmptyStateView(
                        systemImage: "magnifyingglass",
                        title: "Search Messages",
                        message: "Find text across all of your Cipher chats."
                    )
                } else if hits.isEmpty {
                    EmptyStateView(
                        systemImage: "magnifyingglass",
                        title: "No Matches",
                        message: "Try a different phrase."
                    )
                } else {
                    List(hits) { hit in
                        Button {
                            onSelectChat(hit.chatID)
                            dismiss()
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(hit.chatTitle).font(.headline).foregroundStyle(.primary)
                                    Spacer()
                                    Text(CipherDateFormatting.chatList(hit.date))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Text(hit.snippet)
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                    }
                }
            }
            .searchable(text: $query, isPresented: .constant(true), prompt: "Search messages")
            .navigationTitle("Search")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
    }

    private var hits: [SearchHit] {
        store.searchMessages(query: query)
    }
}
