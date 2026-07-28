// Command relay is the Cipher store-and-forward relay.
//
// Design: docs/BACKEND.md. Threat model: docs/THREAT_MODEL.md. The one sentence
// that shapes everything here is that this server is assumed hostile or seizable,
// including when its operator is us — so it holds no plaintext, retains nothing
// past delivery, and has no administrative interface at all.
//
// P4.S02 scaffold: configuration, logging, Postgres, Redis, health. The endpoints
// arrive in P4.S03 onward.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cipher.relay/internal/cache"
	"cipher.relay/internal/config"
	"cipher.relay/internal/health"
	"cipher.relay/internal/httpx"
	"cipher.relay/internal/logging"
	"cipher.relay/internal/store"
)

// healthCheck makes the binary able to probe itself.
//
// The runtime image is `scratch` — no shell, no curl, no wget — so a Docker
// HEALTHCHECK has exactly one executable available to it, and this is it. The
// alternative is a runtime image carrying a shell and a HTTP client purely so
// the orchestrator can make one request, which is a meaningful attack surface
// bought for a trivial convenience.
var healthCheck = flag.Bool("health-check", false,
	"probe the local readiness endpoint, exit 0 if ready; for HEALTHCHECK")

func main() {
	flag.Parse()

	if *healthCheck {
		if err := probeSelf(); err != nil {
			fmt.Fprintf(os.Stderr, "relay: not ready: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		// Written to stderr rather than through the logger: run() can fail
		// before a logger exists, and a startup failure that produces no output
		// is the worst possible failure mode in a container.
		fmt.Fprintf(os.Stderr, "relay: %v\n", err)
		os.Exit(1)
	}
}

// probeSelf requests readiness over the loopback interface.
//
// It reads only RELAY_LISTEN_ADDR, not the full configuration: config.Load
// requires the database and Redis credentials, and a health check that cannot
// run without them would report "unhealthy" for a container whose secrets were
// merely absent from the probe's environment.
func probeSelf() error {
	addr := os.Getenv("RELAY_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("RELAY_LISTEN_ADDR %q: %w", addr, err)
	}

	// Loopback explicitly: the listener may be bound to 0.0.0.0, and probing
	// the wildcard address is not a thing a client can do.
	url := "http://127.0.0.1:" + port + "/health/ready"

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness returned %d", resp.StatusCode)
	}
	return nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	level, recognised := logging.ParseLevel(cfg.LogLevel)
	log := logging.New(os.Stdout, level)
	if !recognised {
		log.Warn("unrecognised RELAY_LOG_LEVEL, defaulting to info",
			slog.String("configured", cfg.LogLevel))
	}

	// Signal handling is installed before any dependency is opened, so a SIGTERM
	// during a slow startup is honoured rather than killing the process mid-way
	// through a migration.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer db.Close()

	applied, err := db.Migrate(ctx)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// Names only. Migration SQL is schema, not secret, but logging its contents
	// would put column names and constraints into every startup line for no gain.
	log.Info("schema up to date", slog.Int("applied", len(applied)),
		slog.Any("migrations", applied))

	redis, err := cache.Open(ctx, cfg.RedisAddr, cfg.RedisPassword)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	defer func() { _ = redis.Close() }()

	// Refuse to run against a Redis that writes to disk. See cache.AssertNoPersistence:
	// persistence is on by default in the standard image, and it would turn the
	// ephemeral tier into an on-disk record of who was talking to whom.
	if err := redis.AssertNoPersistence(ctx); err != nil {
		return err
	}

	healthHandler := health.New(log, time.Second)
	healthHandler.Add("postgres", db)
	healthHandler.Add("redis", redis)

	mux := http.NewServeMux()
	healthHandler.Routes(mux)

	// Log OUTSIDE Recover, not the other way round. See httpx.Chain: the
	// intuitive order silently drops every panicking request from the access log.
	handler := httpx.Chain(mux,
		httpx.Log(log),
		httpx.Recover(log),
		httpx.SecurityHeaders,
		httpx.LimitBody(cfg.MaxRequestBytes),
	)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		// The Go default writes server errors to the standard logger, which is
		// not the redacting one. Routing them through slog keeps every line the
		// process emits subject to the same policy.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", slog.String("addr", cfg.ListenAddr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutting down", slog.Duration("grace", cfg.ShutdownGrace))
	}

	// context.WithoutCancel: ctx is already cancelled by the signal, so deriving
	// the shutdown deadline from it would give in-flight requests no grace at all
	// — a bug that looks like a clean shutdown and drops live connections.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownGrace)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return <-serveErr
}
