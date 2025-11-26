# Data Model: GoSniffer Forward Proxy

**Date**: 2025-11-23
**Context**: Data structures and entities for GoSniffer proxy implementation

## Overview

GoSniffer's data model is lightweight, focusing on certificate management and connection tracking. No persistent database is required; all state is either in-memory (certificate cache, active connections) or filesystem-based (root CA PEM files).

## Core Entities

### 1. Root CA Certificate

**Purpose**: Self-signed certificate authority used to sign dynamically generated leaf certificates for MITM

**Attributes**:
- `PrivateKey`: RSA or ECDSA private key (2048-bit RSA or P-256 ECDSA)
- `Certificate`: X.509 certificate with CA capabilities
- `CertPEM`: PEM-encoded certificate bytes
- `KeyPEM`: PEM-encoded private key bytes
- `Subject`: `pkix.Name` with organization name (e.g., "GoSniffer Root CA")
- `NotBefore`: Certificate validity start time
- `NotAfter`: Certificate validity end time (typically 10 years)
- `SerialNumber`: Unique serial number (`*big.Int`)

**Storage**: Filesystem (PEM files: `ca-cert.pem`, `ca-key.pem`)

**Validation Rules** (from SR-001, SR-003):
- Private key MUST be generated using `crypto/rand.Reader`
- Key size MUST be minimum 2048 bits for RSA or P-256 for ECDSA
- Certificate MUST have `IsCA: true` and `KeyUsageCertSign`
- Serial number MUST be cryptographically random

**Lifecycle**:
1. Generated at first startup if files don't exist
2. Loaded from disk on subsequent startups
3. Logged with SHA-256 fingerprint on generation/load (SR-004)
4. Persists across proxy restarts

**Go Type Mapping**:
```go
type CA struct {
    PrivateKey  crypto.PrivateKey        // *rsa.PrivateKey or *ecdsa.PrivateKey
    Certificate *x509.Certificate
    CertPEM     []byte
    KeyPEM      []byte
}
```

---

### 2. Leaf Certificate

**Purpose**: Dynamically generated certificate for specific hostname, signed by root CA, presented to client during MITM

**Attributes**:
- `Hostname`: Target hostname (e.g., "example.com")
- `PrivateKey`: RSA or ECDSA private key (same type/size as root CA)
- `Certificate`: X.509 certificate with `DNSNames: []string{hostname}`
- `TLSCertificate`: `tls.Certificate` combining cert and key for TLS handshake
- `NotBefore`: Certificate validity start time
- `NotAfter`: Certificate validity end time (typically 30 days)
- `SerialNumber`: Unique serial number per certificate
- `Fingerprint`: SHA-256 hash of certificate (for audit logging)
- `CreatedAt`: Timestamp of generation (for TTL eviction)

**Storage**: In-memory cache (not persisted to disk)

**Validation Rules** (from SR-002, SR-003, SR-004):
- Private key MUST be generated using `crypto/rand.Reader`
- Key size MUST match root CA key size
- Certificate MUST include hostname in Subject Alternative Names (SANs)
- Certificate MUST be signed by root CA private key
- Generation MUST be logged with fingerprint and timestamp

**Lifecycle**:
1. Generated on-demand when CONNECT request arrives for new hostname
2. Cached in-memory to avoid regeneration for repeated requests
3. Evicted from cache based on LRU policy (max 1000 entries) or TTL (30 days)
4. Not persisted; regenerated on proxy restart

**Concurrency Considerations**:
- Multiple concurrent CONNECT requests for same hostname could trigger race condition
- Cache MUST use thread-safe structure (`sync.Map` or mutex-protected map)
- Use `LoadOrStore` pattern to ensure single generation per hostname

**Go Type Mapping**:
```go
type CachedCert struct {
    TLSCertificate tls.Certificate
    Hostname       string
    Fingerprint    string  // SHA-256 hex
    CreatedAt      time.Time
}

type CertCache struct {
    mu     sync.RWMutex
    certs  map[string]*CachedCert  // hostname -> cert
    maxEntries int  // 1000
}
```

---

### 3. Proxy Connection

**Purpose**: Represents an active client connection to the proxy, tracking state for graceful shutdown

**Attributes**:
- `ClientAddr`: `net.Addr` of connecting client
- `Protocol`: "HTTP" or "HTTPS"
- `State`: "active", "draining", "closed"
- `StartTime`: Connection establishment timestamp
- `Context`: `context.Context` for cancellation propagation
- `Cancel`: `context.CancelFunc` to signal shutdown
- `WaitGroup`: `*sync.WaitGroup` for tracking goroutine completion

**Storage**: In-memory tracking (map or slice maintained by proxy server)

**Lifecycle**:
1. Created when client connects (Accept or ServeHTTP call)
2. State transitions: active → draining (on shutdown signal) → closed
3. Removed from tracking when connection fully closed

**Concurrency Considerations**:
- Connection map MUST be thread-safe (mutex-protected)
- Context cancellation used to signal shutdown to active goroutines
- WaitGroup used to wait for goroutine cleanup during graceful shutdown

**Go Type Mapping**:
```go
type Connection struct {
    ClientAddr net.Addr
    Protocol   string
    State      string
    StartTime  time.Time
    Ctx        context.Context
    Cancel     context.CancelFunc
}

type ConnectionTracker struct {
    mu          sync.Mutex
    connections map[string]*Connection  // connID -> connection
    wg          sync.WaitGroup
}
```

---

### 4. Intercepted Request

**Purpose**: Represents an HTTP/HTTPS request passing through the proxy, used for logging and header injection

**Attributes**:
- `Hostname`: Extracted from `Host` header or CONNECT target
- `Method`: HTTP method (GET, POST, CONNECT, etc.)
- `URL`: Request URL
- `Headers`: HTTP headers (map or `http.Header`)
- `Timestamp`: Request arrival time
- `StatusCode`: HTTP response status code (populated after upstream response)

**Storage**: Ephemeral (exists only during request processing, then logged)

**Lifecycle**:
1. Created when HTTP request arrives (parsed from client connection)
2. Headers modified (inject `X-Proxied-By: GoSniffer`)
3. Forwarded to upstream server
4. Response status code recorded
5. Logged to console (hostname and status code)
6. Discarded after logging

**Go Type Mapping**:
```go
// Uses standard library http.Request directly
// Additional fields tracked separately for logging
type RequestLog struct {
    Hostname   string
    StatusCode int
    Timestamp  time.Time
}
```

---

### 5. Log Entry

**Purpose**: Console output record for each proxied request (satisfies FR-006)

**Attributes**:
- `Timestamp`: Request timestamp
- `Hostname`: Target hostname
- `StatusCode`: HTTP response status code

**Format**: Simple text output to stdout
```
[2025-11-23 14:30:45] example.com - 200
[2025-11-23 14:30:46] google.com - 301
[2025-11-23 14:30:47] api.github.com - 403
```

**Storage**: Not stored; streamed to stdout in real-time

**Security Considerations** (SR-008):
- MUST NOT log sensitive data (private keys, auth tokens, request bodies)
- Sanitize hostname to prevent log injection attacks
- Use structured logging format to avoid parsing ambiguity

**Go Type Mapping**:
```go
// No explicit struct; use log.Printf directly
log.Printf("[%s] %s - %d\n", time.Now().Format(time.RFC3339), hostname, statusCode)
```

---

## Data Relationships

```
Root CA (1)
    |
    | signs
    |
    +--> Leaf Certificates (0..N) [cached in memory]
            |
            | used by
            |
            +--> HTTPS Connections (0..N)

Proxy Server (1)
    |
    | tracks
    |
    +--> Connections (0..N)
            |
            | generates
            |
            +--> Intercepted Requests (0..N)
                    |
                    | produces
                    |
                    +--> Log Entries (0..N)
```

## State Transitions

### Leaf Certificate Cache State Machine

```
[Not Exists]
    |
    | CONNECT request arrives for new hostname
    v
[Generating] (mutex locked)
    |
    | Certificate created and signed
    v
[Cached]
    |
    +---> [Evicted] (LRU or TTL expiration)
    |
    +---> [Reused] (subsequent request for same hostname)
```

### Connection State Machine

```
[Connecting]
    |
    | Accept() or ServeHTTP()
    v
[Active]
    |
    +---> [Draining] (shutdown signal received)
    |         |
    |         | Request completes or timeout
    |         v
    |     [Closed]
    |
    +---> [Closed] (error or client disconnect)
```

## Certificate Cache Eviction Policy

**Strategy**: LRU (Least Recently Used) + TTL (Time To Live)

**Parameters**:
- **Max Entries**: 1000 certificates
- **TTL**: 30 days (matches certificate validity period)
- **Eviction Trigger**: On insert when cache is full

**Algorithm**:
1. On cache insert: Check if hostname already exists (return existing if found)
2. If cache size >= 1000: Evict LRU entry (track last-used timestamp)
3. Insert new certificate with `CreatedAt = time.Now()`
4. Background goroutine (runs every hour): Remove entries where `time.Since(CreatedAt) > 30 days`

**Concurrency Safety**:
- All cache operations protected by `sync.RWMutex`
- Reads use `RLock()`, writes use `Lock()`
- Eviction goroutine acquires write lock

**Memory Bounds** (PR-004):
- Each cached cert ~2KB (2048-bit RSA key + cert)
- Max memory: 1000 certs × 2KB = ~2MB
- Acceptable memory footprint for developer tool

## Validation Rules Summary

| Entity | Validation | Constitution Reference |
|--------|-----------|----------------------|
| Root CA Private Key | Must use crypto/rand, 2048-bit RSA or P-256 ECDSA | Principle III, SR-001, SR-003 |
| Leaf Certificate | Must use crypto/rand, match root CA key size | Principle III, SR-002, SR-003 |
| Certificate Operations | Must log with SHA-256 fingerprint | Principle III, SR-004 |
| TLS Configuration | TLS 1.2 minimum, TLS 1.3 preferred | Principle III, SR-006 |
| Certificate Cache | Bounded memory (1000 entries max) | Principle IV, PR-004 |
| Log Entries | No sensitive data (keys, tokens, bodies) | SR-008 |
| Error Handling | All network operations checked, wrapped with context | Principle II |

## File System Structure

```
~/.gosniffer/ (or configurable path)
├── ca-cert.pem          # Root CA certificate (public)
└── ca-key.pem           # Root CA private key (SENSITIVE - restrict permissions)
```

**File Permissions**:
- `ca-cert.pem`: 644 (public readable)
- `ca-key.pem`: 600 (owner read/write only)

**Note**: Users must manually install `ca-cert.pem` into their client's trust store for HTTPS interception to work without certificate warnings.
