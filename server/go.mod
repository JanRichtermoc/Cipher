module cipher.relay

// Raised from 1.25.0 to 1.25.13 for security, not for a language feature.
//
// This line is the relay's toolchain pin: CI installs Go from it
// (`go-version-file: server/go.mod`), so the standard library the release binary
// is built against is whatever is written here. Go 1.25.0's stdlib carries 21
// vulnerabilities that `govulncheck` reaches from this module — most of them in
// crypto/tls, crypto/x509 and net/url, on the TLS handshake and certificate
// paths that face the public internet. 1.25.12 was the lowest release that fixed
// those 21. On 2026-08-14 the vulnerability database gained another reachable
// standard-library set fixed in 1.25.13, so that is now the lowest clean release;
// it is deliberately not a feature-version bump (the same rule AUDIT 1.11
// applied to golang.org/x/text).
//
// 1.25.0 remains the *language* floor measured in P4: pgx v5.10.0 declares
// `go >= 1.25.0` and the build fails under 1.23. That measurement still holds —
// this is a patch bump above it, not a replacement for it.
//
// `Scripts/verify-vulns.sh` scans under exactly this version rather than under
// whatever Go is on the developer's PATH, so raising it here is what moves the
// gate. See AUDIT 1.13.
go 1.25.13

require (
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/redis/go-redis/v9 v9.21.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)
