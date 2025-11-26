# Feature Specification: GoSniffer Forward Proxy

**Feature Branch**: `001-gosniffer-proxy`
**Created**: 2025-11-23
**Status**: Draft
**Input**: User description: "Build a command-line forward proxy named 'GoSniffer' that:
1.  Intercepts both HTTP and HTTPS traffic.
2.  Performs SSL/TLS interception for HTTPS requests using a self-signed root CA.
3.  Logs the hostname and status code for every request to the console.
4.  Allows for request modification, specifically to add a custom header (`X-Proxied-By: GoSniffer`) to all intercepted HTTP requests.
5.  Supports graceful shutdown via SIGINT/SIGTERM signals."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Basic HTTP Traffic Interception (Priority: P1)

A developer or QA engineer configures their browser or application to use GoSniffer as an HTTP proxy. All HTTP requests flow through GoSniffer, which logs each request's hostname and response status code to the console, and automatically adds the custom header to every request before forwarding it upstream.

**Why this priority**: This is the foundational capability. HTTP interception without TLS complexity provides immediate value for debugging non-encrypted traffic and validates the core proxy mechanics.

**Independent Test**: Can be fully tested by configuring a client to use the proxy, making HTTP requests to public sites, and verifying that console logs show hostname/status and that the upstream server receives the custom header.

**Acceptance Scenarios**:

1. **Given** GoSniffer is running on port 8080, **When** a client makes an HTTP GET request to http://example.com, **Then** the console displays "example.com - 200" and the upstream server receives the request with the header `X-Proxied-By: GoSniffer`
2. **Given** GoSniffer is proxying traffic, **When** a request returns a 404 status, **Then** the console logs display the hostname and "404" status code
3. **Given** multiple concurrent HTTP requests are in flight, **When** responses arrive, **Then** all hostname/status pairs are logged correctly without corruption or data races

---

### User Story 2 - HTTPS Traffic Interception with TLS MITM (Priority: P2)

A security researcher or network administrator needs to inspect HTTPS traffic. They install GoSniffer's self-signed root CA into their client's trust store, configure the proxy, and make HTTPS requests. GoSniffer intercepts the TLS connection, performs MITM by presenting a dynamically generated certificate, logs the hostname and status, and injects the custom header.

**Why this priority**: TLS interception is the distinguishing feature for inspecting modern web traffic. However, it depends on the basic proxy infrastructure (P1) being functional first.

**Independent Test**: Can be fully tested by installing the root CA, configuring a client for HTTPS proxy, accessing https://google.com, and verifying console logs show "google.com - 200" and that no certificate errors occur.

**Acceptance Scenarios**:

1. **Given** GoSniffer's root CA is trusted by the client, **When** a client makes an HTTPS GET request to https://example.com, **Then** the TLS handshake completes without certificate warnings and the console displays "example.com - 200"
2. **Given** an HTTPS request is intercepted, **When** GoSniffer forwards the request upstream, **Then** the upstream server receives the custom header `X-Proxied-By: GoSniffer`
3. **Given** GoSniffer generates a certificate for a new hostname, **When** the certificate is presented to the client, **Then** the certificate is signed by the GoSniffer root CA and matches the requested hostname

---

### User Story 3 - Graceful Shutdown (Priority: P3)

An operator running GoSniffer in a terminal or automated environment needs to stop the proxy cleanly. They send a SIGINT (Ctrl+C) or SIGTERM signal. GoSniffer stops accepting new connections, allows in-flight requests to complete (within a timeout), and exits cleanly without leaving orphaned connections or corrupted logs.

**Why this priority**: Graceful shutdown is important for operational reliability but not core to the interception functionality. It can be implemented after the proxy mechanics are working.

**Independent Test**: Can be fully tested by starting GoSniffer, initiating several slow HTTP/HTTPS requests, sending SIGINT, and verifying that active requests complete while new requests are rejected, followed by a clean process exit.

**Acceptance Scenarios**:

1. **Given** GoSniffer is running with active connections, **When** a SIGINT signal is received, **Then** GoSniffer stops accepting new connections and waits for active requests to finish (up to 30 seconds)
2. **Given** the shutdown grace period expires, **When** connections are still active, **Then** GoSniffer forcefully closes remaining connections and exits
3. **Given** a shutdown signal is received with no active connections, **When** the signal is processed, **Then** GoSniffer exits immediately with status code 0

---

### Edge Cases

- What happens when the client does not trust the GoSniffer root CA during an HTTPS request? (Expected: TLS handshake fails with certificate error on client side; GoSniffer logs the connection attempt but cannot intercept)
- What happens when an upstream server is unreachable or times out? (Expected: GoSniffer logs the error and returns an appropriate HTTP error response to the client, e.g., 502 Bad Gateway)
- What happens when a request contains malformed HTTP headers? (Expected: GoSniffer rejects the request and logs the error without crashing)
- What happens when GoSniffer receives a CONNECT request for a non-HTTPS port? (Expected: GoSniffer establishes a TCP tunnel without TLS interception and logs the tunnel establishment)
- What happens when multiple requests arrive for the same hostname concurrently during certificate generation? (Expected: Certificate generation is idempotent or cached; all requests use the same generated certificate without race conditions)

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST accept incoming proxy connections on a configurable listen port (default 8080)
- **FR-002**: System MUST intercept HTTP requests, forward them to the upstream server, and relay responses back to the client
- **FR-003**: System MUST intercept HTTPS requests using the HTTP CONNECT method, establish a TLS connection with the client using a dynamically generated certificate, and forward decrypted traffic upstream over a separate TLS connection
- **FR-004**: System MUST generate a self-signed root CA certificate at startup (or load an existing one if configured)
- **FR-005**: System MUST dynamically generate leaf certificates for intercepted HTTPS hostnames, signed by the root CA
- **FR-006**: System MUST log the hostname and HTTP response status code for every intercepted request to standard output
- **FR-007**: System MUST inject a custom HTTP header `X-Proxied-By: GoSniffer` into all intercepted HTTP and HTTPS requests before forwarding them upstream
- **FR-008**: System MUST register signal handlers for SIGINT and SIGTERM to initiate graceful shutdown
- **FR-009**: During graceful shutdown, system MUST stop accepting new connections while allowing in-flight requests to complete within a timeout period (default 30 seconds)
- **FR-010**: System MUST provide a command-line interface to start the proxy with configurable parameters (listen address, root CA path)

### Assumptions

- Clients are configured to use GoSniffer as an HTTP/HTTPS proxy (proxy auto-discovery is not required)
- For HTTPS interception, users will manually install the GoSniffer root CA into their client's trust store
- The proxy operates as a forward proxy (not a transparent/reverse proxy)
- Logging output format can be simple text (structured logging is not required for MVP)
- Root CA certificate can be stored on disk in PEM format; automatic CA rotation is not required
- Certificate caching strategy will use in-memory storage with reasonable bounds (per constitution principle III)

### Key Entities

- **Root CA Certificate**: A self-signed X.509 certificate with CA capabilities, used to sign dynamically generated leaf certificates. Attributes: private key, certificate (PEM encoded), validity period, subject name.
- **Leaf Certificate**: A dynamically generated X.509 certificate for a specific hostname, signed by the root CA. Attributes: hostname (Subject Alternative Name), private key, certificate, validity period.
- **Proxy Connection**: Represents an active client connection to the proxy. Attributes: client address, protocol (HTTP/HTTPS), state (active, closing), associated request/response metadata.
- **Intercepted Request**: An HTTP request passing through the proxy. Attributes: hostname, method, path, headers (including injected custom header), body.
- **Log Entry**: A record of a proxied request. Attributes: timestamp, hostname, status code.

### Security Requirements

- **SR-001**: Root CA private key MUST use minimum 2048-bit RSA or P-256 ECDSA (per constitution principle III)
- **SR-002**: Leaf certificate private keys MUST use minimum 2048-bit RSA or P-256 ECDSA
- **SR-003**: All certificate generation MUST use cryptographically secure random sources (crypto/rand)
- **SR-004**: Root CA and leaf certificate generation operations MUST be logged with certificate fingerprints for audit trail
- **SR-005**: When validating upstream HTTPS connections, system MUST verify hostname, expiration, and chain of trust (per constitution principle III)
- **SR-006**: TLS version for client and upstream connections MUST support TLS 1.2 minimum, with TLS 1.3 preferred (per constitution principle III)
- **SR-007**: Certificate generation errors MUST abort the connection without fallback to insecure modes
- **SR-008**: System MUST NOT log sensitive data (private keys, authentication tokens, request bodies) to console output

### Performance Requirements

- **PR-001**: Proxy latency overhead MUST be measurable and target <5ms p99 for local connections (per constitution principle IV)
- **PR-002**: System MUST handle at least 100 concurrent connections without degradation
- **PR-003**: Certificate generation for new hostnames MUST complete within 100ms to avoid noticeable request delays
- **PR-004**: Memory usage for certificate caching MUST be bounded to prevent exhaustion under load (per constitution principle III)
- **PR-005**: System MUST include benchmarks for critical paths: connection setup, HTTP relay, HTTPS MITM handshake, and header injection

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can successfully intercept HTTP requests and observe hostname and status code logs in real-time
- **SC-002**: Users can successfully intercept HTTPS requests after installing the root CA, with no certificate errors
- **SC-003**: All intercepted requests (HTTP and HTTPS) include the custom header as verified by upstream server logs or packet inspection
- **SC-004**: The proxy handles at least 100 concurrent connections with <5ms p99 latency overhead
- **SC-005**: Graceful shutdown completes within 30 seconds for typical workloads, with no orphaned connections or process hangs
- **SC-006**: Certificate generation for a new hostname completes in <100ms
- **SC-007**: The system operates continuously for 1 hour under load (50 req/sec mixed HTTP/HTTPS) without crashes or memory leaks
