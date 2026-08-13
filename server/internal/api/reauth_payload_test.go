// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"testing"

	"github.com/google/uuid"
)

// TestTheSigningPayloadMatchesTheSwiftClient pins a contract that spans two
// languages and would otherwise break in production only.
//
// The payload is built independently on each side — here, and in
// `AccountKey.signingPayload` — so nothing but agreement makes them equal. The
// trap is specific: Swift's `UUID.uuidString` is UPPERCASE and Go's
// `uuid.UUID.String()` is lowercase, so a client that used the raw Swift value
// would produce signatures that verify perfectly in its own unit tests and are
// refused by the relay every time.
//
// The expected string below is asserted verbatim by
// `CipherTests/AccountKeyTests.testTheSigningPayloadUsesTheRelaysLowercaseFormatting`.
// If one side changes, this fails rather than the field does.
func TestTheSigningPayloadMatchesTheSwiftClient(t *testing.T) {
	aci := uuid.MustParse("3F2B8C14-0000-4000-8000-ABCDEFABCDEF")
	got := string(SigningPayload(aci, "abc"))
	want := "cipher-reauth-v1:3f2b8c14-0000-4000-8000-abcdefabcdef:abc"
	if got != want {
		t.Fatalf("payload mismatch across languages:\n  go:    %q\n  swift: %q", got, want)
	}
}

// The context string is domain separation, not decoration: without it any other
// place that asks a device to sign a server-chosen blob becomes a signing oracle
// for re-authentication.
func TestTheSigningPayloadCarriesItsContextAndAccount(t *testing.T) {
	aci := uuid.New()
	payload := string(SigningPayload(aci, "chal"))
	if len(payload) <= len("chal") {
		t.Fatal("the payload is the bare challenge")
	}
	if payload[:len(SignatureContext)] != SignatureContext {
		t.Fatalf("payload does not begin with the context: %q", payload)
	}
	if !contains(payload, aci.String()) {
		t.Fatal("the account is not inside what is signed, so a signature is not bound to it")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
