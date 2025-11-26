# HTTP Protocol Contract

**Purpose**: Defines how GoSniffer handles HTTP (non-encrypted) requests

## Request Flow

```
Client --> GoSniffer Proxy --> Upstream Server
         (intercept)        (forward)
```

## HTTP Request Handling

### 1. Client Request Format

Standard HTTP/1.1 request with absolute URI (RFC 2616, Section 5.1.2):

```http
GET http://example.com/path HTTP/1.1
Host: example.com
User-Agent: curl/7.68.0
Accept: */*
```

**Key Characteristics**:
- Method: Any valid HTTP method (GET, POST, PUT, DELETE, etc.)
- Request-URI: MUST be absolute form (includes full URL with scheme and host)
- Headers: Standard HTTP headers from client

### 2. GoSniffer Interception

**Actions Performed**:
1. Parse incoming HTTP request
2. Extract hostname from URL or `Host` header
3. **Inject custom header**: `X-Proxied-By: GoSniffer`
4. Forward modified request to upstream server

**Header Injection (FR-007)**:

Original request:
```http
GET /api/users HTTP/1.1
Host: api.example.com
Authorization: Bearer token123
```

Modified request forwarded upstream:
```http
GET /api/users HTTP/1.1
Host: api.example.com
Authorization: Bearer token123
X-Proxied-By: GoSniffer
```

**Logging (FR-006)**:
- Extract hostname: `api.example.com`
- Wait for upstream response
- Extract status code: e.g., `200`
- Log to stdout: `[2025-11-23 14:30:45] api.example.com - 200`

### 3. Upstream Request

**Transport**: Use `http.DefaultTransport` or custom `http.RoundTripper`

**TLS Configuration** (if proxying to HTTPS upstream):
- Verify upstream certificate (hostname, expiration, chain of trust)
- Support TLS 1.2 minimum, TLS 1.3 preferred
- Do NOT perform MITM on upstream connection (client trust validation)

**Error Handling**:
- Upstream unreachable → Return `502 Bad Gateway` to client
- Upstream timeout → Return `504 Gateway Timeout` to client
- DNS resolution failure → Return `502 Bad Gateway` to client

### 4. Response Relay

**Actions**:
1. Receive response from upstream server
2. Extract status code for logging
3. Relay response headers and body to client without modification

**Response Example**:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 42

{"status": "success", "user_id": 12345}
```

**No modifications**: Response is passed through unchanged (GoSniffer only modifies requests, not responses)

## Error Scenarios

### Malformed HTTP Request

**Condition**: Client sends invalid HTTP (e.g., missing method, malformed headers)

**Response**:
```http
HTTP/1.1 400 Bad Request
Content-Type: text/plain

Invalid HTTP request format
```

**Logging**: Log error without crashing (constitution Principle II)

### Upstream Connection Failure

**Condition**: Upstream server unreachable (network error, DNS failure)

**Response**:
```http
HTTP/1.1 502 Bad Gateway
Content-Type: text/plain

Failed to connect to upstream server
```

**Logging**: Log connection attempt and error details

### Upstream Timeout

**Condition**: Upstream server does not respond within timeout (default 30 seconds)

**Response**:
```http
HTTP/1.1 504 Gateway Timeout
Content-Type: text/plain

Upstream server timeout
```

**Logging**: Log timeout event

## Concurrency Behavior

**Per-Connection Goroutine** (Constitution Principle I):
- Each client connection handled in dedicated goroutine
- No shared mutable state between connections
- Safe for 100+ concurrent HTTP requests

**Context Propagation**:
- Each request has associated `context.Context`
- Cancellation propagates: client disconnect → cancel upstream request
- Shutdown signal → cancel all active requests

## Performance Characteristics

**Latency Overhead** (PR-001):
- Target: <5ms p99 for local connections
- Measured: Time between client request arrival and upstream request send

**Throughput** (PR-002):
- Handle 100+ concurrent HTTP connections
- Sustained: 50 req/sec mixed traffic

## Security Constraints

**Input Validation** (SR-008):
- Sanitize hostname before logging (prevent log injection)
- Validate HTTP method (reject unknown methods)
- Limit request header size (prevent memory exhaustion)

**No Sensitive Data Logging** (SR-008):
- Do NOT log `Authorization` headers
- Do NOT log request bodies
- Do NOT log query parameters (may contain secrets)
- Log ONLY hostname and status code

## Testing Contract

**Integration Test**:
```go
// Pseudo-code
func TestHTTPProxyInterception(t *testing.T) {
    // Setup: Start mock upstream server
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Verify custom header was injected
        assert.Equal(t, "GoSniffer", r.Header.Get("X-Proxied-By"))
        w.WriteHeader(http.StatusOK)
    }))
    defer upstream.Close()

    // Setup: Start GoSniffer proxy
    proxy := StartProxy(":8080")
    defer proxy.Shutdown()

    // Execute: Make HTTP request through proxy
    client := &http.Client{
        Transport: &http.Transport{
            Proxy: func(req *http.Request) (*url.URL, error) {
                return url.Parse("http://localhost:8080")
            },
        },
    }
    resp, err := client.Get(upstream.URL)

    // Verify: Status code 200, no errors
    assert.NoError(t, err)
    assert.Equal(t, 200, resp.StatusCode)
}
```

## RFC References

- **RFC 2616**: HTTP/1.1 protocol specification
- **RFC 7230**: HTTP/1.1 Message Syntax and Routing (updated)
- **RFC 7231**: HTTP/1.1 Semantics and Content
- **Section 5.1.2**: Request-URI absolute form for proxy requests
