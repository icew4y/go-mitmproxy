<!--
Sync Impact Report:
- Version change: [Initial template] → 1.0.0
- Added principles:
  I. Go Concurrency Idioms (NEW)
  II. Rigorous Error Handling (NEW)
  III. Secure TLS Interception (NEW)
  IV. Performance & Efficiency (NEW)
  V. Simplicity & Maintainability (NEW)
- Added sections: Development Practices, Security Requirements
- Removed sections: None
- Templates requiring updates:
  ✅ .specify/memory/constitution.md (this file)
  ✅ .specify/templates/plan-template.md (Constitution Check section updated with all 5 principles)
  ✅ .specify/templates/spec-template.md (Security & Performance Requirements sections added)
  ✅ .specify/templates/tasks-template.md (Concurrency, Security, and Error Handling task categories added)
- Follow-up TODOs: None
-->

# go-mitmproxy Constitution

## Core Principles

### I. Go Concurrency Idioms

The proxy MUST leverage Go's native concurrency primitives for all connection handling:

- Each client connection MUST be handled in a dedicated goroutine
- Inter-goroutine communication MUST use channels, not shared memory with locks
- Connection lifecycle MUST follow structured concurrency patterns (context cancellation,
  proper goroutine cleanup)
- Worker pools MUST be used for CPU-bound operations to prevent goroutine explosion
- All goroutines MUST be bounded and traceable (no fire-and-forget goroutines without
  context or supervision)

**Rationale**: Go's concurrency model is the foundation for high-performance proxy
operations. Idiomatic patterns prevent race conditions, deadlocks, and resource leaks that
would degrade performance or cause instability under load.

### II. Rigorous Error Handling

Network operations are inherently unreliable. The proxy MUST handle all error paths:

- Every network operation (read, write, dial, accept) MUST check errors explicitly
- Errors MUST be wrapped with context using `fmt.Errorf` with `%w` or structured error types
- Connection errors MUST NOT panic; use structured error returns and logging
- Transient errors (timeouts, temporary failures) MUST be distinguished from permanent
  failures and handled appropriately
- Error handling MUST include cleanup (connection close, resource release) via `defer`
  statements
- Public API functions MUST document all possible error return conditions

**Rationale**: Network proxies operate in hostile environments with unreliable connections,
malicious clients, and unexpected protocols. Rigorous error handling ensures the proxy
degrades gracefully rather than crashing or leaking resources.

### III. Secure TLS Interception

TLS interception is a security-critical operation requiring strict controls:

- Certificate generation MUST use cryptographically secure random sources (`crypto/rand`)
- Private keys MUST use minimum 2048-bit RSA or P-256 ECDSA
- Generated certificates MUST be logged with fingerprints for auditability
- Certificate caching MUST be time-bounded and memory-limited to prevent exhaustion
- Certificate validation MUST verify hostname, expiration, and chain of trust for upstream
  connections
- TLS version MUST be configurable with secure defaults (TLS 1.2 minimum, TLS 1.3 preferred)
- Certificate generation errors MUST abort the connection, not fall back to insecure modes

**Rationale**: MITM proxies handle sensitive data and trust relationships. Poor certificate
handling creates vulnerabilities (weak crypto, certificate spoofing) and makes incident
investigation impossible without audit trails.

### IV. Performance & Efficiency

The proxy MUST maintain high throughput with minimal overhead:

-Latency overhead MUST be measured and kept under 5ms p99 for local connections
- Memory allocations MUST be minimized in hot paths (use buffer pools, zero-copy where
  possible)
- Goroutine creation overhead MUST be amortized via worker pools for short-lived operations
- CPU profiling and memory profiling MUST be available via pprof endpoints
- Benchmarks MUST exist for critical paths (connection setup, data relay, TLS handshake)
- Performance regressions MUST be detected via benchmark comparisons in CI

**Rationale**: Proxies sit in the critical path of all traffic. Performance degradation
directly impacts user experience and system scalability. Measurable performance goals
enable detection of regressions before deployment.

### V. Simplicity & Maintainability

Proxy logic is complex enough without unnecessary abstractions:

- Code MUST prioritize readability over cleverness (clear > concise)
- Abstractions MUST solve concrete problems, not hypothetical futures (YAGNI)
- Dependencies MUST be justified (prefer standard library over third-party where feasible)
- Public APIs MUST be minimal and stable (hard to misuse)
- Magic numbers MUST be named constants with comments explaining their origin
- Complex protocol logic MUST include references to specifications (RFC numbers, section
  citations)

**Rationale**: Proxy code operates at the intersection of multiple complex protocols (HTTP,
TLS, TCP). Unnecessary complexity compounds debugging difficulty and increases the attack
surface. Simplicity enables faster incident response and easier security audits.

## Development Practices

### Testing Requirements

- **Unit tests** MUST cover error paths, not just happy paths
- **Integration tests** MUST verify end-to-end proxy behavior with real TLS handshakes
- **Concurrency tests** MUST use `go test -race` to detect data races
- **Benchmark tests** MUST exist for performance-critical code paths
- Tests MUST NOT depend on external services (use local test servers)
- Tests MUST be deterministic (no timing-dependent assertions without timeouts)

### Code Review Standards

- All changes MUST be reviewed for concurrency safety (race conditions, deadlocks)
- Security-critical code (TLS, certificate handling) MUST receive additional scrutiny
- Performance claims MUST be backed by benchmark data
- Error handling MUST be complete (no ignored errors without explicit justification)

## Security Requirements

### Mandatory Security Practices

- Input validation MUST assume all client data is malicious
- Log injection MUST be prevented (sanitize user-controlled data in logs)
- DoS protection MUST include connection limits, rate limiting, and timeout enforcement
- Dependencies MUST be scanned for known vulnerabilities (e.g., `govulncheck`)
- Security issues MUST be reported privately and patched before public disclosure

### Audit & Compliance

- Certificate generation events MUST be logged with timestamps and fingerprints
- Connection failures MUST be logged with sufficient detail for debugging
- Sensitive data (private keys, auth tokens) MUST NOT appear in logs or error messages
- Security-relevant configuration changes MUST be auditable

## Governance

### Amendment Procedure

This constitution defines the non-negotiable principles for go-mitmproxy development.
Amendments require:

1. Documented justification for the change
2. Review of impact on existing code and templates
3. Update of version number following semantic versioning
4. Synchronization of dependent templates and documentation

### Versioning Policy

- **MAJOR** version: Backward-incompatible governance changes (principle removal/redefinition)
- **MINOR** version: New principle added or materially expanded guidance
- **PATCH** version: Clarifications, wording improvements, non-semantic refinements

### Compliance Review

- All feature specifications MUST reference constitution principles in requirements
- All implementation plans MUST include a Constitution Check gate
- All PRs MUST verify compliance with applicable principles
- Deviations MUST be explicitly justified and documented in complexity tracking tables

**Version**: 1.0.0 | **Ratified**: 2025-11-23 | **Last Amended**: 2025-11-23
