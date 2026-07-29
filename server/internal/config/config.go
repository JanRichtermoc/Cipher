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

	// MaxRequestBytes caps any request body. The largest legitimate body is an
	// envelope (65567 bytes by Envelope.swift) plus JSON framing; attachments go
	// to a separate streaming route in P4.S09 that does not use this limit.
	MaxRequestBytes int64
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
	}

	if len(problems) > 0 {
		return Config{}, errors.New("configuration: " + strings.Join(problems, "; "))
	}
	return cfg, nil
}
