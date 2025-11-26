# Research: GoSniffer Implementation Approach

**Date**: 2025-11-23
**Context**: Determining whether to use third-party MITM proxy library (goproxy) or custom stdlib implementation for GoSniffer forward proxy

## Decision: Custom Implementation Using Go Standard Library

## Rationale:

Based on the project's constitution (Principle V: Simplicity & Maintainability - "prefer standard library over third-party where feasible") and the specific security/performance requirements, a **custom implementation using only Go standard library** is the recommended approach. While `elazarl/goproxy` is a mature library, the stdlib-only approach provides:

1. **Better alignment with constitution principles**: Direct control over security (Principle III), performance optimizations (Principle IV), and reduced dependency surface
2. **Sufficient complexity for the use case**: GoSniffer's requirements are focused and well-defined, not requiring the extensive feature set of goproxy
3. **Learning and maintainability**: The codebase remains fully transparent and auditable without needing to understand third-party abstractions
4. **Security concerns**: goproxy has known CVE (CVE-2023-37788, HIGH severity CVSS 7.5) and shows reduced maintenance activity

## Alternatives Considered:

### Option 1: github.com/elazarl/goproxy

**Pros:**
- Mature library with 10+ years of production use
- Built-in MITM support with certificate generation and caching
- Fluent API design: `proxy.OnRequest(conditions).Do(handler)` pattern
- Handles complex edge cases (HTTP/2, websockets, connection hijacking)
- Certificate caching mechanisms to reduce CPU overhead
- ~5,749 lines of code with 243 functions provide battle-tested implementations

**Cons:**
- **Security concern**: CVE-2023-37788 (HIGH severity, CVSS 7.5) - Denial of Service vulnerability
- **Maintenance concerns**: Package shows "Inactive" maintenance status
- **Complexity overhead**: Library provides features beyond GoSniffer's requirements (websocket support, complex filtering, middleware chains)
- **Abstraction layer**: Adds indirection that obscures certificate generation, TLS configuration, and connection handling
- **Constitution violation**: Principle V states "Dependencies MUST be justified (prefer standard library over third-party where feasible)"
- **Security audit burden**: 5,749 LOC library requires ongoing vulnerability monitoring and updates
- **Limited control**: Certificate generation parameters, TLS version enforcement, and audit logging may not fully match security requirements (SR-001 through SR-008)

**Complexity:** Medium - The library abstracts away most MITM complexity but requires learning its handler patterns and understanding its certificate management model. Integration requires ~200-300 LOC but introduces 5,749 LOC dependency.

### Option 2: Custom Implementation (Go Standard Library Only)

**Pros:**
- **Full control over security**: Direct implementation of constitution Principle III requirements (crypto/rand usage, key sizes, certificate fingerprint logging, TLS version control)
- **Performance optimization**: Hot paths can be optimized with buffer pools, zero-copy techniques aligned with Principle IV
- **Zero third-party dependencies**: Satisfies Principle V ("prefer stdlib")
- **Simplified audit surface**: Only custom code needs security review, not external library
- **Educational value**: Team gains deep understanding of HTTP CONNECT, TLS handshakes, certificate generation
- **Minimal viable complexity**: Implement only what GoSniffer needs (HTTP/HTTPS proxy, MITM, header injection, logging)
- **Clear error handling**: All network operations under direct control for rigorous error handling (Principle II)
- **Examples available**: Multiple blog posts and tutorials demonstrate stdlib-only MITM proxy implementations in 100-300 LOC

**Cons:**
- **Development time**: Requires implementing HTTP CONNECT handling, TLS certificate generation, and connection tunneling from scratch (~500-800 LOC estimated)
- **Edge case handling**: Must manually handle connection lifecycle, HTTP protocol edge cases, certificate validation
- **Initial testing burden**: More integration tests needed to validate MITM handshake, certificate generation, concurrent connections
- **Potential for bugs**: No battle-testing; team must discover and fix edge cases (malformed requests, timeout handling, certificate caching race conditions)
- **Certificate cache implementation**: Must implement bounded LRU/TTL cache manually (vs built-in with goproxy)

**Complexity:** Medium-High - Requires understanding of:
- HTTP CONNECT method and connection hijacking (`http.Hijacker` interface)
- TLS certificate generation (`crypto/x509.CreateCertificate`, serial numbers, SANs)
- Bidirectional TCP stream copying with goroutines (`io.Copy`, proper cleanup)
- Certificate caching with concurrency safety
- Graceful shutdown coordination across active goroutines

However, complexity is **bounded and transparent** - all code is visible and controllable.

## Implementation Notes for Chosen Approach:

### Key Technical Components

**1. HTTP Proxy Handler** (~100 LOC)
- Use `net/http.Server` with custom handler checking `req.Method == http.MethodConnect`
- For HTTP: Parse request, inject header, forward with `http.DefaultTransport`, relay response
- For HTTPS CONNECT: Hijack connection, respond "200 Connection Established", proceed to MITM

**2. TLS MITM Implementation** (~150 LOC)
- Extract hostname from CONNECT request (e.g., `example.com:443`)
- Generate/retrieve leaf certificate for hostname from cache
- Establish `tls.Server` connection with client using generated cert
- Dial upstream with `tls.Dial`, verify certificate chain
- Bidirectional copy: `go io.Copy(client, upstream)` and `io.Copy(upstream, client)`
- Ensure goroutine cleanup with `defer` and context cancellation

**3. Certificate Authority Module** (~200 LOC)
- **Root CA generation**: `x509.Certificate` with `IsCA: true`, `KeyUsageKeyEncipherment | KeyUsageCertSign`, 2048-bit RSA or P-256 ECDSA key via `crypto/rand.Reader`
- **Leaf certificate generation**: Template with `DNSNames: []string{hostname}`, signed by root CA private key, validity period 30 days
- **Certificate caching**: `sync.Map` or mutex-protected `map[string]*tls.Certificate` with LRU eviction (max 1000 entries) and TTL cleanup goroutine
- **Audit logging**: Log SHA-256 fingerprint on each certificate generation (satisfy SR-004)

**4. Graceful Shutdown** (~100 LOC)
- Register `signal.Notify` for `os.Interrupt`, `syscall.SIGTERM`
- On signal: Call `server.Shutdown(ctx)` with 30-second timeout context
- Track active connections using `sync.WaitGroup` or context cancellation
- Forcefully close connections after timeout

### Critical Challenges to Address

**Challenge 1: Connection Hijacking Complexity**
- **Issue**: `http.Hijacker.Hijack()` returns raw `net.Conn`; must handle TLS wrapping, bidirectional copying, and cleanup manually
- **Solution**: Create helper function `func tunnelTLS(clientConn net.Conn, hostname string, ca *CA)` that encapsulates TLS establishment and io.Copy loops with proper defer cleanup

**Challenge 2: Certificate Generation Race Conditions**
- **Issue**: Multiple concurrent CONNECT requests for same hostname could trigger parallel certificate generation
- **Solution**: Use `sync.Map` with `LoadOrStore` pattern or mutex-protected map with double-checked locking to ensure single certificate generation per hostname

**Challenge 3: Upstream TLS Verification**
- **Issue**: Need to verify upstream server certificates while performing MITM on client side
- **Solution**: Use `tls.Config{InsecureSkipVerify: false}` with custom `VerifyConnection` callback to log verification results (satisfy SR-005)

**Challenge 4: Error Propagation Across Goroutines**
- **Issue**: Errors in io.Copy goroutines (e.g., upstream timeout) must cleanly close both sides of tunnel
- **Solution**: Use `context.WithCancel()` and defer `cancel()` in both copy goroutines; any error cancels context and breaks other goroutine's Read

**Challenge 5: HTTP Request Parsing After TLS Decryption**
- **Issue**: After MITM TLS handshake with client, need to parse decrypted HTTP requests and inject headers
- **Solution**: Wrap client TLS connection in `bufio.Reader`, use `http.ReadRequest`, modify headers, serialize with `req.Write(upstreamConn)`

### Standard Library Packages Required

**Core Networking**:
- `net/http`: Server, Request, Response, Transport
- `net`: Conn, Listener, Dial
- `crypto/tls`: Config, Certificate, Server handshake, Client dial

**Certificate Management**:
- `crypto/x509`: Certificate, CreateCertificate, CertPool
- `crypto/x509/pkix`: Name (for certificate subject/issuer)
- `crypto/rsa`: GenerateKey, PrivateKey
- `crypto/ecdsa`: GenerateKey (for P-256 option)
- `crypto/rand`: Reader (for secure random generation)
- `encoding/pem`: Encode/Decode for PEM file format

**Concurrency & Control**:
- `context`: Context, WithCancel, WithTimeout
- `sync`: Mutex, RWMutex, Map, WaitGroup
- `os/signal`: Notify for SIGINT/SIGTERM
- `syscall`: Signal constants

**Utilities**:
- `io`: Copy, ReadAll, MultiWriter
- `bufio`: Reader, Writer (for HTTP parsing)
- `log`: Printf for console output
- `flag`: Command-line argument parsing
- `crypto/sha256`: Certificate fingerprint generation

### Implementation Roadmap

**Phase 1: Basic HTTP Proxy** (P1 - User Story 1)
- Implement HTTP request forwarding without MITM
- Header injection for HTTP traffic
- Logging hostname and status codes
- Validate with curl and browser tests

**Phase 2: Root CA and Certificate Generation** (P2 - User Story 2 foundation)
- Root CA generation and persistence (PEM files)
- Leaf certificate generation with proper SANs
- Certificate fingerprint logging
- Unit tests for certificate validity and key strength

**Phase 3: HTTPS MITM** (P2 - User Story 2)
- CONNECT method handling and connection hijacking
- TLS handshake with client using generated certs
- Upstream TLS connection establishment
- Bidirectional tunnel with goroutines and proper cleanup
- Integration tests with trusted root CA

**Phase 4: Certificate Caching and Performance** (Performance requirements)
- Implement bounded certificate cache with LRU/TTL
- Add benchmarks for connection setup and certificate generation
- Optimize hot paths (buffer reuse, allocation reduction)
- Race detector testing (`go test -race`)

**Phase 5: Graceful Shutdown** (P3 - User Story 3)
- Signal handling and shutdown coordination
- Connection draining with timeout
- Integration tests for clean exit

**Estimated Implementation**: ~500-800 LOC core logic + ~400-600 LOC tests

### Testing Strategy

- **Unit tests**: Certificate generation, cache operations, header injection, error paths
- **Integration tests**: End-to-end HTTP/HTTPS proxy with real TLS handshakes using `httptest.NewTLSServer`
- **Concurrency tests**: Run with `-race` flag, test 100+ concurrent connections
- **Benchmark tests**: Connection setup, HTTP relay, HTTPS MITM handshake, certificate generation (<100ms requirement)
- **Manual tests**: Browser configuration with installed root CA, curl commands with proxy settings

### Reference Implementations

1. [Building an HTTP Proxy with MITM Inspection in Go](https://agst.dev/posts/tls-http-proxy-go/) - Complete tutorial with certificate generation
2. [Go and Proxy Servers: Part 2 - HTTPS Proxies](https://eli.thegreenplace.net/2022/go-and-proxy-servers-part-2-https-proxies/) - Working MITM implementation with commented code
3. [HTTP(S) Proxy in Golang in less than 100 lines of code](https://medium.com/@mlowicki/http-s-proxy-in-golang-in-less-than-100-lines-of-code-6a51c2f2c38c) - Minimal example using stdlib
4. [Puzzle ITC: How does an HTTP Proxy work?](https://www.puzzle.ch/blog/2024/08/09/learn-with-go-how-does-an-http-proxy-work) - Step-by-step with code snapshots

## Constitution Alignment

This decision aligns with all five constitution principles:

**I. Go Concurrency Idioms**: ✅
- Each connection handled in dedicated goroutine
- Channels used for shutdown coordination
- Context cancellation for cleanup

**II. Rigorous Error Handling**: ✅
- All network operations will have explicit error checks
- Errors wrapped with context using `fmt.Errorf` with `%w`
- Defer statements for cleanup

**III. Secure TLS Interception**: ✅
- Full control over crypto/rand usage
- Explicit key size enforcement (2048-bit RSA / P-256 ECDSA)
- Certificate fingerprint logging for audit trail
- TLS version control (1.2 min, 1.3 preferred)

**IV. Performance & Efficiency**: ✅
- Benchmarks planned for all critical paths
- Certificate caching with bounded memory
- Buffer pool opportunities in hot paths

**V. Simplicity & Maintainability**: ✅
- Zero third-party dependencies
- Clear, readable stdlib code
- Minimal abstraction layers
- Full transparency for security audits
