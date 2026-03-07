# CLAUDE.md - harderdns

## Project Overview

**harderdns** is a DNS proxy server written in Go that queries multiple upstream DNS servers concurrently and returns the first successful response. It improves DNS reliability through parallel queries, retries, and timeout handling.

## Architecture

Single-file Go application (`main.go`, ~480 lines). Key components:

- **`resolve()`** - Sends a single DNS query to one upstream server
- **`harder()`** - Core logic: spawns goroutines to query all upstreams concurrently, returns first successful response
- **`handleDnsRequest()`** - Main request handler: checks localhost, static hosts, then proxies upstream
- **`reloadHosts()`** - Loads static DNS records from `hosts.json` (triggered by SIGHUP)
- **`event()` / `logger()`** - Thread-safe logging and statistics

## Build & Run

```bash
# Build
go build -o harderdns main.go

# Run (upstreams are positional args)
go run main.go 1.1.1.1:53 8.8.8.8:53

# Development mode
go run main.go -devMode -resolv -resolvSearch time -stats 1 1.1.1.1:53

# Docker
docker build -t harderdns .
docker-compose up
```

## Testing

Integration tests use Docker Compose:
```bash
docker-compose -f tests/docker-compose.yml up
```

There are no Go unit tests. The test suite runs `dig` queries against the server in a container.

## Key Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-dialTimeout` | 101 | Dial timeout (ms) |
| `-readTimeout` | 500 | Read timeout (ms) |
| `-writeTimeout` | 500 | Write timeout (ms) |
| `-delay` | 10 | Retry delay (ms) |
| `-concurrencyDelay` | 0 | Stagger between upstream queries (ms) |
| `-tries` | 3 | Max retry attempts per upstream |
| `-netMode` | "udp" | Protocol: udp, tcp, tcp-tls |
| `-edns0` | -1 | EDNS0 buffer size (-1 = disabled) |
| `-stats` | -1 | Print stats interval in seconds (-1 = disabled) |
| `-resolv` | false | Integrate with system resolv.conf |
| `-hosts` | "" | Path to hosts.json file |

## Dependencies

- Go 1.17
- `github.com/miekg/dns` - DNS protocol library
- `github.com/google/uuid` - Request ID generation
- `github.com/IGLOU-EU/go-wildcard` - Wildcard host matching
- `github.com/docker/libnetwork` - resolv.conf parsing

## CI/CD

GitHub Actions (`.github/workflows/docker.yml`): builds and pushes multi-platform Docker images (amd64/arm64) to `ghcr.io` on push/PR to main.

## Code Conventions

- All state is in package-level globals (no struct-based architecture)
- Concurrency uses goroutines + channels + context cancellation
- Logging uses mutex-protected `println()` via `logger()`
- Statistics tracked in `events` map, protected by `eventMutex`
- SIGHUP triggers hosts.json reload
