// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"
	"time"
)

// setEnv sets the minimum viable configuration, and t.Setenv restores it after.
func setEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RELAY_DATABASE_URL", "postgres://u:p@postgres:5432/db")
	t.Setenv("RELAY_REDIS_ADDR", "redis:6379")
	t.Setenv("RELAY_REDIS_PASSWORD", "redis-password")
}

func TestLoadRequiresEverySecret(t *testing.T) {
	// The point of this test is not that Load fails — it is that it fails for
	// *each* secret independently. A fallback quietly added to any one of them
	// would otherwise be caught only if it happened to be the one left unset.
	for _, missing := range []string{
		"RELAY_DATABASE_URL", "RELAY_REDIS_ADDR", "RELAY_REDIS_PASSWORD",
	} {
		t.Run(missing, func(t *testing.T) {
			setEnv(t)
			t.Setenv(missing, "")

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() succeeded with %s unset — it has acquired a default", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Fatalf("error does not name %s: %v", missing, err)
			}
		})
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	// Restart-fix-restart against a container is slow, and reporting only the
	// first problem means the second is discovered after the first is fixed.
	t.Setenv("RELAY_DATABASE_URL", "")
	t.Setenv("RELAY_REDIS_ADDR", "")
	t.Setenv("RELAY_REDIS_PASSWORD", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected failure")
	}
	for _, key := range []string{"RELAY_DATABASE_URL", "RELAY_REDIS_ADDR", "RELAY_REDIS_PASSWORD"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error omits %s: %v", key, err)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", cfg.ReadHeaderTimeout)
	}
	// The largest legitimate body is an envelope (65567 bytes) plus framing, so
	// the cap must comfortably exceed that and not be unbounded.
	if cfg.MaxRequestBytes < 65567 {
		t.Errorf("MaxRequestBytes = %d, too small for a maximum envelope", cfg.MaxRequestBytes)
	}
}

func TestLoadRejectsMalformedDurations(t *testing.T) {
	setEnv(t)
	t.Setenv("RELAY_READ_TIMEOUT", "fifteen seconds")

	if _, err := Load(); err == nil {
		t.Fatal("expected a malformed duration to fail startup")
	}
}

func TestLoadRejectsNonPositiveValues(t *testing.T) {
	// A zero timeout means "no timeout" in net/http, so accepting it would turn
	// a typo into an unbounded slowloris window.
	setEnv(t)
	t.Setenv("RELAY_READ_HEADER_TIMEOUT", "0s")

	if _, err := Load(); err == nil {
		t.Fatal("expected a non-positive timeout to fail startup")
	}
}

func TestLoadRejectsNonPositiveBodyLimit(t *testing.T) {
	setEnv(t)
	t.Setenv("RELAY_MAX_REQUEST_BYTES", "-1")

	if _, err := Load(); err == nil {
		t.Fatal("expected a negative body limit to fail startup")
	}
}

func TestTrustedProxiesDefaultsToTrustingNobody(t *testing.T) {
	// The safe default, and the one the P4 threat reasoning depends on: an
	// operator who never sets this gets a relay that believes no forwarding
	// header from anyone. Silence must not mean "trust loopback" — a convenience
	// default here is a rate-limit bypass on any host where something untrusted
	// can reach the relay over loopback.
	setEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Fatalf("TrustedProxies defaulted to %v, want empty", cfg.TrustedProxies)
	}
}

func TestTrustedProxiesParsesCIDRsAndBareAddresses(t *testing.T) {
	setEnv(t)
	t.Setenv("RELAY_TRUSTED_PROXY", "172.18.0.0/16, 127.0.0.1 ,::1")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := make([]string, 0, len(cfg.TrustedProxies))
	for _, p := range cfg.TrustedProxies {
		got = append(got, p.String())
	}
	want := []string{"172.18.0.0/16", "127.0.0.1/32", "::1/128"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestTrustedProxiesRefusesJunkRatherThanIgnoringIt(t *testing.T) {
	// A typo must stop startup. Skipping an unparseable entry would leave the
	// operator believing a proxy is trusted when it is not — which presents as
	// an intermittent, load-dependent rate-limit fault long after deployment.
	for _, bad := range []string{"not-an-ip", "172.18.0.0/33", "127.0.0.1:8080", "example.com"} {
		t.Run(bad, func(t *testing.T) {
			setEnv(t)
			t.Setenv("RELAY_TRUSTED_PROXY", bad)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted %q as a trusted proxy", bad)
			}
		})
	}
}

func TestTrustedProxiesMasksHostBits(t *testing.T) {
	// 10.0.0.7/8 is what someone writes when they mean 10.0.0.0/8. Contains()
	// would still behave, but the parsed value is also what gets logged and
	// eyeballed, and it should say what it means.
	setEnv(t)
	t.Setenv("RELAY_TRUSTED_PROXY", "10.0.0.7/8")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.TrustedProxies[0].String(); got != "10.0.0.0/8" {
		t.Fatalf("got %q, want 10.0.0.0/8", got)
	}
}
