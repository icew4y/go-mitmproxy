# HTTPS MITM Protocol Contract

**Purpose**: Defines how GoSniffer performs TLS man-in-the-middle interception for HTTPS traffic

## Request Flow

```
Client --[TLS]-->  GoSniffer Proxy  --[TLS]--> Upstream Server
              (MITM intercept)
         [Decrypt]  [Modify]  [Re-encrypt]
```

## HTTPS CONNECT Method Handling

### 1. Client CONNECT Request

Client initiates HTTPS proxy tunnel using HTTP CONNECT method (RFC 7231, Section 4.3.6):

```http
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
```

**Key Characteristics**:
- Method: `CONNECT`
- Request-URI: `hostname:port` (target server)
- No request body
- Client expects `200 Connection Established` before sending TLS ClientHello

### 2. GoSniffer CONNECT Response

**Success Response**:
```http
HTTP/1.1 200 Connection Established\r\n
\r\n
```

**No headers**: Minimal response to signal tunnel is ready

**Error Response** (e.g., invalid hostname):
```http
HTTP/1.1 400 Bad Request\r\n
Content-Type: text/plain\r\n
\r\n
Invalid CONNECT target
```

### 3. Connection Hijacking

**Action**: After sending `200 Connection Established`, GoSniffer hijacks the TCP connection

**Go Implementation Pattern**:
```go
hijacker, ok := w.(http.Hijacker)
if !ok {
    return errors.New("response writer does not support hijacking")
}
clientConn, _, err := hijacker.Hijack()
if err != nil {
    return fmt.Errorf("hijack failed: %w", err)
}
defer clientConn.Close()

// clientConn is now a raw net.Conn
// GoSniffer controls all subsequent bytes
```

**Connection State**: From this point, GoSniffer has full control over raw TCP stream

## TLS MITM Handshake

### 4. Client TLS Handshake (GoSniffer as Server)

**Step 1**: Client sends TLS ClientHello to GoSniffer

**Step 2**: GoSniffer responds as TLS server using dynamically generated leaf certificate

**Certificate Generation**:
1. Extract hostname from CONNECT target (e.g., `example.com`)
2. Check certificate cache: `cert, ok := cache.Get(hostname)`
3. If not cached: Generate new leaf certificate signed by root CA
4. Return `tls.Certificate` with private key

**TLS Configuration** (SR-006):
```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{leafCert},
    MinVersion:   tls.VersionTLS12,  // TLS 1.2 minimum
    MaxVersion:   tls.VersionTLS13,  // TLS 1.3 preferred
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        // TLS 1.3 suites (automatically enabled with MaxVersion TLS13)
        tls.TLS_AES_256_GCM_SHA384,
        tls.TLS_AES_128_GCM_SHA256,
    },
}
tlsConn := tls.Server(clientConn, tlsConfig)
err := tlsConn.Handshake()
```

**Certificate Requirements** (SR-001, SR-002, SR-003):
- Private key: 2048-bit RSA or P-256 ECDSA
- Generated using `crypto/rand.Reader`
- Subject Alternative Names (SANs): `[]string{hostname}`
- Signed by root CA
- Valid for 30 days

**Certificate Validation Failure** (Client-Side):
- If root CA not trusted by client → TLS handshake fails with certificate error
- Client sees warning: "Certificate issued by unknown authority"
- GoSniffer logs connection attempt but cannot decrypt traffic

### 5. Upstream TLS Handshake (GoSniffer as Client)

**Step 1**: GoSniffer establishes TLS connection to upstream server

**TLS Configuration** (SR-005, SR-006):
```go
upstreamConfig := &tls.Config{
    ServerName:         hostname,  // For SNI and certificate validation
    InsecureSkipVerify: false,     // MUST verify upstream certificate
    MinVersion:         tls.VersionTLS12,
    MaxVersion:         tls.VersionTLS13,
    VerifyConnection: func(cs tls.ConnectionState) error {
        // Custom verification logic
        // Log certificate chain, expiration, hostname match
        return verifyUpstreamCert(cs, hostname)
    },
}
upstreamConn, err := tls.Dial("tcp", hostname+":443", upstreamConfig)
```

**Certificate Verification** (SR-005):
- Verify hostname matches certificate Common Name or SANs
- Verify certificate not expired
- Verify chain of trust to trusted root CAs
- Log verification result (success or failure)

**Upstream Connection Failure**:
- Certificate validation fails → Return `502 Bad Gateway` to client, close TLS connection
- Upstream unreachable → Return `502 Bad Gateway`
- Upstream timeout → Return `504 Gateway Timeout`

## Decrypted Traffic Handling

### 6. HTTP Request Parsing (After TLS Decryption)

**Step 1**: Read decrypted HTTP request from client TLS connection

```go
reader := bufio.NewReader(tlsClientConn)
req, err := http.ReadRequest(reader)
if err != nil {
    return fmt.Errorf("failed to parse HTTP request: %w", err)
}
```

**Step 2**: Inject custom header (FR-007)
```go
req.Header.Set("X-Proxied-By", "GoSniffer")
```

**Step 3**: Forward modified request to upstream TLS connection
```go
err = req.Write(upstreamConn)
if err != nil {
    return fmt.Errorf("failed to write to upstream: %w", err)
}
```

### 7. HTTP Response Relay

**Step 1**: Read response from upstream TLS connection
```go
resp, err := http.ReadResponse(bufio.NewReader(upstreamConn), req)
if err != nil {
    return fmt.Errorf("failed to read upstream response: %w", err)
}
```

**Step 2**: Extract status code for logging (FR-006)
```go
statusCode := resp.StatusCode
log.Printf("[%s] %s - %d\n", time.Now().Format(time.RFC3339), hostname, statusCode)
```

**Step 3**: Write response to client TLS connection
```go
err = resp.Write(tlsClientConn)
if err != nil {
    return fmt.Errorf("failed to write response to client: %w", err)
}
```

## Bidirectional Tunnel (Alternative Approach)

**Note**: Steps 6-7 above show request/response parsing. An alternative is raw bidirectional copying:

```go
// After establishing both TLS connections (client and upstream)
var wg sync.WaitGroup
wg.Add(2)

// Client -> Upstream
go func() {
    defer wg.Done()
    io.Copy(upstreamConn, tlsClientConn)
    upstreamConn.Close()
}()

// Upstream -> Client
go func() {
    defer wg.Done()
    io.Copy(tlsClientConn, upstreamConn)
    tlsClientConn.Close()
}()

wg.Wait()
```

**Limitation**: Raw tunnel approach does NOT allow header injection or logging per-request (only per-connection). **GoSniffer MUST use HTTP parsing approach** to satisfy FR-006 and FR-007.

## Certificate Generation Contract

### Leaf Certificate Requirements

**Certificate Template**:
```go
template := &x509.Certificate{
    SerialNumber: generateSerialNumber(),  // Crypto-random big.Int
    Subject: pkix.Name{
        Organization: []string{"GoSniffer Proxy"},
        CommonName:   hostname,
    },
    DNSNames:              []string{hostname},  // SAN for hostname validation
    NotBefore:             time.Now(),
    NotAfter:              time.Now().Add(30 * 24 * time.Hour),  // 30 days
    KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
    ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    BasicConstraintsValid: true,
    IsCA:                  false,
}

certDER, err := x509.CreateCertificate(
    rand.Reader,        // Crypto-random source (SR-003)
    template,
    rootCA.Certificate, // Parent certificate
    &leafPrivKey.PublicKey,
    rootCA.PrivateKey,  // Signing key
)
```

**Audit Logging** (SR-004):
```go
fingerprint := sha256.Sum256(certDER)
log.Printf("[CERT] Generated certificate for %s (fingerprint: %x)\n", hostname, fingerprint)
```

### Certificate Cache Contract

**Cache Key**: Hostname (e.g., `example.com`)

**Cache Value**:
```go
type CachedCert struct {
    TLSCertificate tls.Certificate
    Hostname       string
    Fingerprint    string
    CreatedAt      time.Time
}
```

**Cache Operations**:
- **Get**: `cert, ok := cache.Get(hostname)` (RLock)
- **Put**: `cache.Put(hostname, cert)` (Lock)
- **Evict**: LRU when size > 1000, or TTL > 30 days

**Concurrency Safety** (Constitution Principle I):
- All cache operations protected by `sync.RWMutex`
- Certificate generation under write lock to prevent duplicate generation race

## Error Handling

### Certificate Generation Failure (SR-007)

**Condition**: Key generation or certificate signing fails

**Action**: **MUST abort connection**, do NOT fall back to plaintext

```go
cert, err := ca.GenerateCertificate(hostname)
if err != nil {
    log.Printf("[ERROR] Certificate generation failed for %s: %v\n", hostname, err)
    clientConn.Close()  // Abort, do not proceed
    return fmt.Errorf("certificate generation failed: %w", err)
}
```

**Client Behavior**: Connection terminated, client receives no response

### TLS Handshake Failure

**Condition**: Client TLS handshake fails (e.g., protocol version mismatch, cipher suite incompatibility)

**Action**: Log error, close connection
```go
err := tlsConn.Handshake()
if err != nil {
    log.Printf("[ERROR] TLS handshake failed: %v\n", err)
    return fmt.Errorf("TLS handshake failed: %w", err)
}
```

### Upstream Certificate Validation Failure (SR-005)

**Condition**: Upstream server certificate invalid (expired, wrong hostname, untrusted CA)

**Action**: Close connection, return error to client
```go
upstreamConn, err := tls.Dial("tcp", upstream, upstreamConfig)
if err != nil {
    log.Printf("[ERROR] Upstream TLS validation failed: %v\n", err)
    return fmt.Errorf("upstream TLS failed: %w", err)
}
```

## Concurrency Behavior

**Per-Connection Goroutines** (Constitution Principle I):
1. Main goroutine: Handles CONNECT, hijacks connection
2. TLS goroutine: Establishes client and upstream TLS connections
3. Request/response goroutines: Parse and forward HTTP within TLS tunnel

**Context Cancellation**:
- Shutdown signal → Cancel all active MITM connections
- Client disconnect → Cancel upstream connection
- Upstream disconnect → Close client connection

## Performance Characteristics

**Certificate Generation** (PR-003):
- Target: <100ms per hostname
- Cached certificates: <1ms (map lookup)

**Latency Overhead** (PR-001):
- Additional overhead vs HTTP: TLS handshakes (client + upstream)
- Target total: <5ms p99 for local connections
- Measured: Time from CONNECT arrival to first decrypted byte forwarded

## Security Constraints

**Certificate Strength** (SR-001, SR-002):
- Root CA: 2048-bit RSA or P-256 ECDSA
- Leaf certs: Match root CA key type and size

**TLS Version** (SR-006):
- Client-facing: TLS 1.2 minimum, TLS 1.3 preferred
- Upstream: TLS 1.2 minimum, TLS 1.3 preferred

**Audit Trail** (SR-004):
- Log every certificate generation with fingerprint
- Log every TLS connection establishment (hostname, timestamp)

**No Insecure Fallback** (SR-007):
- Certificate generation failure → abort connection
- TLS handshake failure → close connection
- Do NOT fall back to plaintext HTTP

## Testing Contract

**Integration Test**:
```go
func TestHTTPSMITMInterception(t *testing.T) {
    // Setup: Install root CA in test client trust store
    rootCA := loadRootCA()
    certPool := x509.NewCertPool()
    certPool.AddCert(rootCA.Certificate)

    // Setup: Start mock HTTPS upstream server
    upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "GoSniffer", r.Header.Get("X-Proxied-By"))
        w.WriteHeader(http.StatusOK)
    }))
    defer upstream.Close()

    // Setup: Start GoSniffer proxy
    proxy := StartProxy(":8080", rootCA)
    defer proxy.Shutdown()

    // Execute: Make HTTPS request through proxy with root CA trusted
    client := &http.Client{
        Transport: &http.Transport{
            Proxy: func(req *http.Request) (*url.URL, error) {
                return url.Parse("http://localhost:8080")
            },
            TLSClientConfig: &tls.Config{
                RootCAs: certPool,  // Trust GoSniffer root CA
            },
        },
    }
    resp, err := client.Get(upstream.URL)

    // Verify: Status code 200, no TLS errors
    assert.NoError(t, err)
    assert.Equal(t, 200, resp.StatusCode)
}
```

## RFC References

- **RFC 7231, Section 4.3.6**: HTTP CONNECT method for tunnel establishment
- **RFC 5246**: TLS 1.2 protocol specification
- **RFC 8446**: TLS 1.3 protocol specification
- **RFC 5280**: X.509 certificate format and validation
- **RFC 6125**: Certificate hostname validation
