// Package cache owns the Redis client.
//
// Redis holds only ephemeral state (docs/BACKEND.md §3): rate-limit counters,
// delivery presence, upload quota. Losing all of it costs at most some in-flight
// rate-limit state, and that property is what keeps Redis from becoming a second
// retention channel.
//
// The rule that makes it true is enforced at the server, not here: persistence
// must be off (no RDB, no AOF). It is ON by default in the standard image, and
// leaving it on would silently write the routing metadata this design works to
// keep off disk into a dump file. [Client.AssertNoPersistence] checks it at
// startup rather than trusting the compose file to have been written correctly.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package cache

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps the Redis client.
type Client struct {
	rdb *redis.Client
}

// Open connects and verifies reachability.
func Open(ctx context.Context, addr, password string) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     16,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return &Client{rdb: rdb}, nil
}

// Close releases the client.
func (c *Client) Close() error { return c.rdb.Close() }

// Ping reports whether Redis is reachable. Used by readiness only.
func (c *Client) Ping(ctx context.Context) error { return c.rdb.Ping(ctx).Err() }

// Scripter exposes the client for Lua evaluation.
//
// Narrowed to [redis.Scripter] rather than returning *redis.Client: the rate
// limiter needs to run a script and nothing else, and handing it the full client
// would let a future edit reach for GET/SET and store something in the tier that
// is documented as holding nothing durable.
func (c *Client) Scripter() redis.Scripter { return c.rdb }

// AssertNoPersistence fails if Redis would write state to disk.
//
// This is a startup assertion, not a nicety. The compose file disables RDB and
// AOF, but a compose file is a claim about a running process and this is the
// process itself being asked. A relay that starts against a persistent Redis
// has quietly acquired an on-disk record of who was talking to whom, and nothing
// else in the system would notice.
//
// Refusing to start is the correct response: the alternative is a warning in a
// log nobody reads, on the one deployment where it mattered.
func (c *Client) AssertNoPersistence(ctx context.Context) error {
	// `save` is a space- or newline-separated list of "<seconds> <changes>"
	// rules. Empty means snapshotting is off.
	save, err := c.configValue(ctx, "save")
	if err != nil {
		return err
	}
	if strings.TrimSpace(save) != "" {
		return fmt.Errorf(
			"redis RDB snapshotting is enabled (save=%q); it must be disabled, "+
				"see docs/BACKEND.md §3", save)
	}

	appendonly, err := c.configValue(ctx, "appendonly")
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(appendonly), "no") {
		return fmt.Errorf(
			"redis AOF is enabled (appendonly=%q); it must be disabled, "+
				"see docs/BACKEND.md §3", appendonly)
	}

	return nil
}

// configValue reads one CONFIG GET parameter.
//
// A missing parameter is an error rather than an empty string. Treating "not
// reported" as "empty" would make AssertNoPersistence pass against a Redis that
// refused to answer — a check that succeeds because it ran nothing, which this
// project has been bitten by before and now refuses on principle.
func (c *Client) configValue(ctx context.Context, name string) (string, error) {
	values, err := c.rdb.ConfigGet(ctx, name).Result()
	if err != nil {
		return "", fmt.Errorf("redis CONFIG GET %s: %w", name, err)
	}
	value, ok := values[name]
	if !ok {
		return "", fmt.Errorf("redis did not report the %q parameter", name)
	}
	return value, nil
}
