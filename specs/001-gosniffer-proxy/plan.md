# Implementation Plan: GoSniffer Forward Proxy

**Branch**: `001-gosniffer-proxy` | **Date**: 2025-11-23 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/001-gosniffer-proxy/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

GoSniffer is a command-line forward proxy that intercepts HTTP and HTTPS traffic, performing TLS MITM using a self-signed root CA. The proxy logs hostname and status codes to console, injects a custom header (`X-Proxied-By: GoSniffer`) into all requests, and supports graceful shutdown. Implementation uses Go with standard library for core proxy logic, crypto/x509 for certificate management, and goroutines for concurrent connection handling.

## Technical Context

**Language/Version**: Go 1.21+ (requires generics support and modern crypto APIs)
**Primary Dependencies**:
- Standard library only (zero third-party dependencies per constitution Principle V)
- Core: `net/http`, `crypto/tls`, `crypto/x509`, `crypto/rsa`, `crypto/ecdsa`, `crypto/rand`
- Supporting: `context`, `os/signal`, `sync`, `log`, `io`, `bufio`, `flag`
- See research.md for detailed stdlib package breakdown

**Storage**: Filesystem (PEM-encoded root CA certificate and private key); in-memory cache for generated leaf certificates
**Testing**: `go test` with `-race` flag for concurrency testing; `testing/httptest` for mock servers; benchmarks using `testing.B`
**Target Platform**: Cross-platform CLI (Linux, macOS, Windows) - single static binary
**Project Type**: Single project (command-line tool)
**Performance Goals**:
- <5ms p99 latency overhead for local connections
- Handle 100+ concurrent connections
- Certificate generation <100ms per hostname
- Sustained throughput of 50 req/sec mixed HTTP/HTTPS

**Constraints**:
- Must use crypto/rand for all key generation (no math/rand)
- Root CA and leaf keys must be minimum 2048-bit RSA or P-256 ECDSA
- TLS 1.2 minimum, TLS 1.3 preferred
- Memory-bounded certificate cache (prevent exhaustion)
- Graceful shutdown within 30 seconds

**Scale/Scope**: Single-user developer tool; designed for local testing/debugging with moderate traffic (not production proxy at scale)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Status**: ✅ **PASSED** (after Phase 1 design review)

**I. Go Concurrency Idioms**
- [x] Connection handling uses dedicated goroutines with proper cleanup (research.md: per-connection goroutines with defer cleanup)
- [x] Inter-goroutine communication uses channels (not shared memory + locks) (shutdown uses channels for coordination)
- [x] Context cancellation propagates through goroutine hierarchies (context.WithCancel for error propagation)
- [x] Worker pools are used for CPU-bound operations (if applicable) (N/A - I/O bound proxy, no CPU-intensive operations)

**II. Rigorous Error Handling**
- [x] All network operations check errors explicitly (contracts mandate error checking for all network ops)
- [x] Errors are wrapped with context (`fmt.Errorf` with `%w`) (research.md specifies error wrapping pattern)
- [x] Transient vs permanent errors are distinguished (HTTP 502 vs 504 for different upstream failures)
- [x] Cleanup is guaranteed via `defer` statements (research.md: defer clientConn.Close() pattern)
- [x] Public API error conditions are documented (data-model.md documents validation rules and error conditions)

**III. Secure TLS Interception** *(if feature involves TLS)*
- [x] Certificate generation uses `crypto/rand` (data-model.md: MUST use crypto/rand.Reader, research.md confirms)
- [x] Private keys meet minimum strength requirements (2048-bit RSA / P-256 ECDSA) (SR-001, SR-002 in spec; data-model.md validates)
- [x] Certificate operations are logged with fingerprints (data-model.md: SHA-256 fingerprint logging required)
- [x] Certificate caching has bounds (time + memory limits) (data-model.md: max 1000 entries, 30-day TTL, ~2MB total)
- [x] TLS validation checks hostname, expiration, chain of trust (https-mitm-protocol.md: VerifyConnection callback)
- [x] TLS version requirements are met (TLS 1.2 min, 1.3 preferred) (https-mitm-protocol.md: explicit MinVersion/MaxVersion)

**IV. Performance & Efficiency** *(if feature is performance-critical)*
- [x] Latency impact measured and within budget (<5ms p99 overhead) (PR-001 in spec; benchmarks planned in research.md)
- [x] Hot paths minimize allocations (buffer pools, zero-copy) (research.md identifies buffer pool opportunities)
- [x] Benchmarks exist for critical operations (tests/benchmarks/ in project structure; PR-005 mandates benchmarks)
- [x] pprof endpoints available for profiling (research.md: CPU/memory profiling with pprof)

**V. Simplicity & Maintainability**
- [x] Code prioritizes readability over cleverness (research decision: clear stdlib code over complex library)
- [x] Abstractions solve concrete problems (YAGNI applied) (research: implement only what GoSniffer needs, no extra features)
- [x] Dependencies are justified (prefer stdlib) (research decision: ZERO third-party dependencies, stdlib only)
- [x] Public APIs are minimal and hard to misuse (pkg/ structure with focused modules: ca, proxy, logger)
- [x] Magic numbers are named constants with explanatory comments (data-model.md: validation rules documented)
- [x] Protocol logic references specifications (RFC numbers) (contracts include RFC 2616, 7231, 5246, 8446 references)

**Gate Evaluation**: ✅ All constitution principles satisfied. Proceed to implementation.

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
go-mitmproxy/
├── cmd/
│   └── gosniffer/
│       └── main.go           # CLI entry point, flag parsing, signal handlers
├── pkg/
│   ├── ca/
│   │   ├── ca.go             # Root CA generation and management
│   │   ├── cert.go           # Leaf certificate generation
│   │   └── cache.go          # Certificate cache with LRU/TTL eviction
│   ├── proxy/
│   │   ├── proxy.go          # HTTP proxy server, connection handling
│   │   ├── handler.go        # HTTP request/response interception
│   │   ├── mitm.go           # HTTPS MITM logic (CONNECT handling)
│   │   └── shutdown.go       # Graceful shutdown coordinator
│   └── logger/
│       └── logger.go         # Request logging (hostname, status code)
├── tests/
│   ├── integration/
│   │   ├── http_test.go      # End-to-end HTTP interception tests
│   │   ├── https_test.go     # End-to-end HTTPS MITM tests
│   │   └── shutdown_test.go  # Graceful shutdown integration tests
│   ├── unit/
│   │   ├── ca_test.go        # Unit tests for CA generation
│   │   ├── cert_test.go      # Unit tests for certificate generation
│   │   ├── cache_test.go     # Unit tests for certificate cache
│   │   └── proxy_test.go     # Unit tests for proxy logic
│   └── benchmarks/
│       ├── proxy_bench_test.go    # Connection setup, relay benchmarks
│       └── cert_bench_test.go     # Certificate generation benchmarks
├── go.mod
├── go.sum
└── README.md
```

**Structure Decision**: Standard Go project layout using `cmd/` for main entry point and `pkg/` for reusable library code. This follows Go community conventions and enables clear separation of concerns:
- `cmd/gosniffer/` contains CLI-specific code (flags, signal handling, main)
- `pkg/ca/` isolates certificate authority logic (satisfies requirement for separate CA module)
- `pkg/proxy/` contains core proxy mechanics (HTTP/HTTPS handling, MITM, shutdown)
- `pkg/logger/` provides centralized logging for hostname/status output
- `tests/` separates integration, unit, and benchmark tests for clarity

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

**Status**: ✅ No violations. All constitution checks passed.

No complexity justifications required. The design adheres to all constitution principles:
- Zero third-party dependencies (stdlib only)
- Standard Go project structure (cmd/, pkg/, tests/)
- Simple, focused modules (ca, proxy, logger)
- Clear separation of concerns without over-abstraction

---

## Planning Phase Summary

**Phase 0: Research** ✅ COMPLETED
- **Artifact**: `research.md`
- **Decision**: Custom stdlib implementation (no third-party libraries)
- **Rationale**: Constitution Principle V compliance, full security control, reduced attack surface
- **Key findings**: ~500-800 LOC implementation, 5 critical challenges identified with solutions

**Phase 1: Design & Contracts** ✅ COMPLETED
- **Artifact**: `data-model.md`
  - 5 core entities defined (Root CA, Leaf Cert, Proxy Connection, Intercepted Request, Log Entry)
  - Certificate cache eviction policy (LRU + TTL, max 1000 entries)
  - State machines for cert cache and connections
  - Validation rules mapped to constitution principles
- **Artifact**: `contracts/http-protocol.md`
  - HTTP request flow, header injection, logging, error handling
  - RFC references (2616, 7230, 7231)
- **Artifact**: `contracts/https-mitm-protocol.md`
  - HTTPS CONNECT handling, TLS MITM handshake, certificate generation
  - Bidirectional tunnel, upstream validation
  - RFC references (7231, 5246, 8446, 5280, 6125)
- **Artifact**: `quickstart.md`
  - Build instructions, HTTP/HTTPS testing procedures
  - Root CA installation guides (Linux, macOS, Windows, Firefox)
  - Troubleshooting guide, example test scenarios
- **Artifact**: `CLAUDE.md` (agent context updated)

**Constitution Check**: ✅ PASSED (all 5 principles satisfied)

**Phase 2: TLS Fingerprint Spoofing Extension** ✅ DESIGN ADDED (User Story 4)
- **Purpose**: Enable mimicking of browser TLS Client Hello fingerprints to bypass detection
- **Technical Approach**:
  - **Challenge**: Go's `crypto/tls` does not expose APIs to fully customize TLS Client Hello
  - **Options Evaluated**:
    1. **Custom fork of `crypto/tls`**: Full control, but maintenance burden and complexity
    2. **utls library** (github.com/refraction-networking/utls): Production-ready TLS fingerprinting library
  - **Decision**: Use `utls` library (constitution Principle V exception - documented below)
  - **Rationale**:
    - `utls` is specifically designed for TLS fingerprinting (used by Tor, censorship circumvention tools)
    - Active maintenance, security audits, proven in production
    - ~10k LOC external dependency vs ~2-3k LOC custom implementation + ongoing maintenance
    - Risk mitigation: Isolated to fingerprinting module, can be made optional feature flag
- **Architecture**:
  - New package: `pkg/tls/fingerprint.go` (fingerprint profiles)
  - Fingerprint profiles: Chrome 120+, Firefox 121+, Safari 17+ (cipher suites, curves, extensions)
  - Custom profile support via JSON configuration
  - Integration: Override `tls.Config` in `pkg/proxy/mitm.go` when establishing upstream connections
- **Data Storage**: Fingerprint profiles as Go structs; custom profiles from JSON files
- **Performance Target**: <5ms overhead for fingerprint application (pre-computed configs)
- **Security Considerations**:
  - Validate fingerprint configs to ensure TLS 1.2+ minimum (SR-010)
  - Log fingerprint selection for audit trail
  - Graceful fallback: If fingerprint incompatible with server, log error and fail connection (no insecure fallback)

**Constitution Exception - User Story 4**:
- **Principle V (Prefer stdlib)**: TLS fingerprint spoofing requires `utls` third-party library
- **Justification**: Impossible with stdlib - Go's `crypto/tls` intentionally hides ClientHello internals
- **Mitigation**:
  - Feature flag `--enable-tls-fingerprint` (default: disabled) - users opt-in
  - Isolated to `pkg/tls/` package - core proxy remains stdlib-only
  - Regular `govulncheck` scans on `utls` dependency
  - Document dependency and security implications in README
  - Core proxy (User Stories 1-3) remains zero-dependency

**Next Step**: Run `/speckit.tasks` to generate implementation tasks (tasks.md)

**Readiness**: Design is complete and validated. Implementation can begin immediately following task generation.
