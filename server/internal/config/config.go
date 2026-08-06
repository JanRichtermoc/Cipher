// Package config loads the relay's configuration from the environment.
//
// Two rules, both of which exist because the opposite is the common default:
//
//   - **Secrets have no defaults.** A missing database password fails startup; it
//     never falls back to something convenient. A development default is a
//     production credential the day someone forgets to override it, and the
//     failure is silent because the service starts fine.
//   - **Nothing is read from a file in the image.** Configuration arrives as
//     environment variables, so a leaked image contains no credentials.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved configuration. Fields are values, not accessors,
// because everything is validated at load time and nothing is re-read later.
type Config struct {
	// ListenAddr is the address the HTTP server binds *inside* the container.
	// Which interface it is reachable on from outside is a Compose concern, and
	// in P4 that is 127.0.0.1 only.
	ListenAddr string

	// DatabaseURL is a libpq-style connection string.
	DatabaseURL string

	// RedisAddr is host:port. Redis holds only ephemeral state (BACKEND.md §3).
	RedisAddr     string
	RedisPassword string

	LogLevel string

	// BlobDir is where attachment bytes live. On the filesystem rather than in
	// Postgres: shredding a file is one unlink, whereas a deleted BYTEA persists
	// in table bloat and WAL until vacuum catches up (docs/BACKEND.md §2.8).
	BlobDir string

	// ReadHeaderTimeout bounds the slowloris window: a client that opens a
	// connection and dribbles headers holds a goroutine until this fires.
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration

	// ShutdownGrace is how long in-flight requests get on SIGTERM.
	ShutdownGrace time.Duration

	// MaxRequestBytes caps request bodies on every route that does not own its
	// own limit. The largest body under it is an envelope (65567 bytes by
	// Envelope.swift) plus JSON framing.
	//
	// **It is not "the largest body the API has", and reading it that way was a
	// bug.** Two routes are exempt and cap themselves, because both legitimately
	// exceed anything the other routes could receive: attachment upload streams
	// megabytes (api.MaxBlobBytes) and prekey publication sends a pool of ML-KEM
	// keys (api.MaxPublishBytes). Publication was *not* exempt until AUDIT 5.32 —
	// this limit silently refused every real client publication while the relay's
	// own validator declared them legal. api.BodyLimitExemptPrefixes names the
	// exempt routes; raising this value is not the way to admit a new large one.
	MaxRequestBytes int64

	// RateLimitPepper keys the rate limiter's subject hashes (ratelimit.Subject).
	//
	// **Optional, and both settings are a real trade-off rather than one being
	// obviously right.** Empty means the relay generates a fresh 32-byte pepper
	// at startup, which is the P4 behaviour:
	//
	//   - Configured: buckets survive a restart. Without it, anything that can
	//     make the process restart — a crash loop, a deploy, an OOM — hands every
	//     caller a fresh allowance, which is a bypass of the invite-redemption
	//     brute-force limit and the prekey-drain limit at the same time
	//     (AUDIT 5.24).
	//   - Configured: the bucket keys become stable for the lifetime of the
	//     value, so a Redis dump taken twice can be correlated. That is the cost,
	//     and it is why this is not simply mandatory.
	//
	// A deployment that is not restarted casually should set it. Rotating it
	// resets every bucket once, which is the same effect a restart used to have.
	RateLimitPepper []byte

	// TrustedProxies are the peers whose X-Real-IP header may be believed.
	//
	// **Empty means trust nobody**, which is the P4 behaviour: the header is
	// ignored and the TCP peer is the client. That default is the safe one in
	// both directions — an unconfigured relay behind a proxy over-throttles
	// (every request shares one bucket), where an unconfigured relay that
	// trusted the header would under-throttle to the point of having no limit
	// at all, since a client could mint a fresh bucket per request.
	//
	// This is a list of *networks*, not hostnames: the check runs per request
	// on the address of the peer that actually connected, and a name would have
	// to be resolved by something an attacker can influence.
	//
	// See httpx.RealIP for what is done with it, and docs/BACKEND.md §9.2 for
	// why the value is deployment-specific rather than a constant.
	TrustedProxies []netip.Prefix
}

// Load reads and validates configuration, returning every problem at once.
//
// Every problem at once, rather than the first: a chain of restart-fix-restart
// against a container is slow, and the second missing variable is discovered
// only after the first is fixed.
func Load() (Config, error) {
	var problems []string

	require := func(key string) string {
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			problems = append(problems, key+" is required and has no default")
		}
		return v
	}

	optional := func(key, fallback string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return fallback
	}

	duration := func(key string, fallback time.Duration) time.Duration {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			return fallback
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s is not a duration: %q", key, raw))
			return fallback
		}
		if d <= 0 {
			problems = append(problems, key+" must be positive")
			return fallback
		}
		return d
	}

	// prefixes parses a comma-separated list of CIDRs or bare addresses.
	//
	// A bare address is widened to a single-host prefix rather than rejected:
	// "127.0.0.1" is what an operator writes, and refusing it would invite the
	// guess "127.0.0.1/0", which trusts the entire internet.
	prefixes := func(key string) []netip.Prefix {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			return nil
		}
		var out []netip.Prefix
		for _, field := range strings.Split(raw, ",") {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			if p, err := netip.ParsePrefix(field); err == nil {
				// Masked so a prefix written with host bits set — 10.0.0.7/8 —
				// still matches the network the operator meant.
				out = append(out, p.Masked())
				continue
			}
			if a, err := netip.ParseAddr(field); err == nil {
				a = a.Unmap()
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			problems = append(problems,
				fmt.Sprintf("%s: %q is neither an IP address nor a CIDR block", key, field))
		}
		return out
	}

	// secret reads an optional secret and enforces a minimum length.
	//
	// Hex or base64 would both be reasonable; raw bytes are accepted so an
	// operator can use `openssl rand -hex 32` or a passphrase without having to
	// know which. The floor is what matters: a two-character pepper is worse than
	// none, because it looks configured.
	secret := func(key string, minLen int) []byte {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			return nil
		}
		if len(raw) < minLen {
			problems = append(problems,
				fmt.Sprintf("%s must be at least %d characters", key, minLen))
			return nil
		}
		return []byte(raw)
	}

	bytesLimit := func(key string, fallback int64) int64 {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			return fallback
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			problems = append(problems, key+" must be a positive integer")
			return fallback
		}
		return n
	}

	cfg := Config{
		ListenAddr: optional("RELAY_LISTEN_ADDR", ":8080"),

		// Required, no fallback: see the package comment.
		DatabaseURL: require("RELAY_DATABASE_URL"),
		RedisAddr:   require("RELAY_REDIS_ADDR"),

		// Required even in development. Redis with no password on a shared
		// Docker network is reachable by every other container on it, and the
		// habit of running it open is how it ends up open somewhere that matters.
		RedisPassword: require("RELAY_REDIS_PASSWORD"),

		LogLevel: optional("RELAY_LOG_LEVEL", "info"),

		// A default is fine here: this is a path, not a secret, and a wrong one
		// fails loudly at startup when the directory cannot be created.
		BlobDir: optional("RELAY_BLOB_DIR", "/var/lib/cipher/blobs"),

		ReadHeaderTimeout: duration("RELAY_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       duration("RELAY_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      duration("RELAY_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:       duration("RELAY_IDLE_TIMEOUT", 60*time.Second),
		ShutdownGrace:     duration("RELAY_SHUTDOWN_GRACE", 15*time.Second),

		MaxRequestBytes: bytesLimit("RELAY_MAX_REQUEST_BYTES", 128*1024),

		// 32 characters, matching the 32 random bytes the fallback generates.
		RateLimitPepper: secret("RELAY_RATELIMIT_PEPPER", 32),

		// No default, and no error when absent: running with no proxy in front
		// is a legitimate configuration (it is how the integration suite and
		// local development run), and it is the strict one.
		TrustedProxies: prefixes("RELAY_TRUSTED_PROXY"),
	}

	if len(problems) > 0 {
		return Config{}, errors.New("configuration: " + strings.Join(problems, "; "))
	}
	return cfg, nil
}
