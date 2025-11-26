# GoSniffer Quickstart Guide

**Purpose**: Step-by-step guide to build, configure, and test GoSniffer forward proxy

## Prerequisites

- Go 1.21+ installed (`go version` to verify)
- Basic understanding of HTTP proxies and TLS certificates
- Command-line terminal (bash, zsh, PowerShell, or cmd)

## Build from Source

### 1. Initialize Go Module

```bash
cd go-mitmproxy
go mod init github.com/yourusername/go-mitmproxy
go mod tidy
```

**Note**: GoSniffer uses zero third-party dependencies. `go mod tidy` will only add Go standard library references.

### 2. Build the Binary

```bash
go build -o bin/gosniffer ./cmd/gosniffer
```

**Output**: Binary at `bin/gosniffer` (or `bin/gosniffer.exe` on Windows)

### 3. Verify Build

```bash
./bin/gosniffer --help
```

**Expected Output**:
```
Usage of gosniffer:
  -addr string
        Listen address for proxy (default ":8080")
  -ca-cert string
        Path to root CA certificate file (default "~/.gosniffer/ca-cert.pem")
  -ca-key string
        Path to root CA private key file (default "~/.gosniffer/ca-key.pem")
```

## First Run: HTTP Interception (User Story 1)

### Step 1: Start GoSniffer

```bash
./bin/gosniffer -addr :8080
```

**Expected Output**:
```
[2025-11-23 14:30:00] GoSniffer proxy starting on :8080
[2025-11-23 14:30:00] Root CA loaded from /home/user/.gosniffer/ca-cert.pem
[2025-11-23 14:30:00] Fingerprint: a1b2c3d4e5f6...
[2025-11-23 14:30:00] Proxy ready. Press Ctrl+C to stop.
```

**Note**: On first run, GoSniffer will generate a new root CA certificate and save it to `~/.gosniffer/`.

### Step 2: Configure Client to Use Proxy

**Option A: Environment Variables (Linux/macOS)**
```bash
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080
```

**Option B: Browser Configuration**
- Firefox: Settings → Network Settings → Manual proxy configuration
  - HTTP Proxy: `localhost` Port: `8080`
  - Also use this proxy for HTTPS: ✓
- Chrome: Settings → System → Open proxy settings (OS-level configuration)

**Option C: Command-line tools**
```bash
# curl
curl -x http://localhost:8080 http://example.com

# wget
wget -e use_proxy=yes -e http_proxy=localhost:8080 http://example.com
```

### Step 3: Test HTTP Interception

```bash
curl -x http://localhost:8080 http://httpbin.org/get
```

**GoSniffer Console Output**:
```
[2025-11-23 14:31:15] httpbin.org - 200
```

**Verify Custom Header Injection**:
```bash
curl -x http://localhost:8080 http://httpbin.org/headers
```

**Response** (check for `X-Proxied-By`):
```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.68.0",
    "X-Proxied-By": "GoSniffer"
  }
}
```

✅ **Success**: HTTP interception working correctly

---

## HTTPS Interception (User Story 2)

### Step 1: Install Root CA Certificate

**Why**: For HTTPS MITM to work without certificate warnings, clients must trust GoSniffer's root CA.

#### Linux (Ubuntu/Debian)

```bash
# Copy root CA to system trust store
sudo cp ~/.gosniffer/ca-cert.pem /usr/local/share/ca-certificates/gosniffer.crt
sudo update-ca-certificates
```

#### macOS

```bash
# Add to system keychain and trust
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.gosniffer/ca-cert.pem
```

#### Windows (PowerShell as Administrator)

```powershell
# Import into Trusted Root Certification Authorities
$certPath = "$env:USERPROFILE\.gosniffer\ca-cert.pem"
Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\Root
```

#### Firefox (Browser-Specific)

1. Open Settings → Privacy & Security → Certificates → View Certificates
2. Click "Authorities" tab → "Import"
3. Select `~/.gosniffer/ca-cert.pem`
4. Check "Trust this CA to identify websites"
5. Click OK

### Step 2: Test HTTPS Interception

```bash
curl -x http://localhost:8080 https://httpbin.org/headers
```

**Expected Behavior**:
- **No certificate warnings** (if root CA installed correctly)
- GoSniffer console shows: `[2025-11-23 14:35:20] httpbin.org - 200`
- Response includes `"X-Proxied-By": "GoSniffer"`

**Certificate Verification**:
```bash
openssl s_client -connect httpbin.org:443 -proxy localhost:8080
```

**Check Certificate**:
- Issuer: `O = GoSniffer Root CA`
- Subject: `CN = httpbin.org`

✅ **Success**: HTTPS MITM working correctly

---

## Graceful Shutdown (User Story 3)

### Step 1: Start Proxy with Active Connections

Terminal 1 (GoSniffer):
```bash
./bin/gosniffer -addr :8080
```

Terminal 2 (Client - simulate slow request):
```bash
curl -x http://localhost:8080 http://httpbin.org/delay/10
```

### Step 2: Send Shutdown Signal

In Terminal 1, press **Ctrl+C** (SIGINT)

**Expected Console Output**:
```
^C[2025-11-23 14:40:30] Shutdown signal received, stopping gracefully...
[2025-11-23 14:40:30] Waiting for 1 active connection(s) to finish...
[2025-11-23 14:40:40] httpbin.org - 200
[2025-11-23 14:40:40] All connections closed. Exiting.
```

**Behavior**:
- Active request completes successfully (10 second delay finishes)
- New connections rejected during shutdown
- Process exits cleanly after 30 seconds or when all connections close

✅ **Success**: Graceful shutdown working correctly

---

## Development Workflow

### Running Tests

**Unit Tests**:
```bash
go test ./pkg/... -v
```

**Integration Tests**:
```bash
go test ./tests/integration/... -v
```

**Concurrency Tests (Race Detector)**:
```bash
go test ./... -race
```

**Benchmarks**:
```bash
go test ./tests/benchmarks/... -bench=. -benchmem
```

**Example Benchmark Output**:
```
BenchmarkProxyHTTP-8             5000    250000 ns/op    1024 B/op    15 allocs/op
BenchmarkProxyHTTPS-8            2000    550000 ns/op    2048 B/op    25 allocs/op
BenchmarkCertGeneration-8        1000   1500000 ns/op   16384 B/op   150 allocs/op
```

**Performance Validation** (from PR-001, PR-003):
- HTTP proxy: <5ms p99 latency
- Certificate generation: <100ms

### Code Coverage

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

**Target Coverage**: >80% for critical paths (proxy, CA, certificate generation)

---

## Configuration Options

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Listen address for proxy server |
| `-ca-cert` | `~/.gosniffer/ca-cert.pem` | Path to root CA certificate |
| `-ca-key` | `~/.gosniffer/ca-key.pem` | Path to root CA private key |
| `-shutdown-timeout` | `30s` | Graceful shutdown timeout |
| `-max-cache` | `1000` | Maximum cached certificates |
| `-cert-ttl` | `720h` (30 days) | Certificate TTL in cache |

### Example: Custom CA Path

```bash
./bin/gosniffer -addr :9090 -ca-cert /etc/gosniffer/ca.crt -ca-key /etc/gosniffer/ca.key
```

### Example: Production Settings

```bash
./bin/gosniffer \
  -addr :8080 \
  -shutdown-timeout 60s \
  -max-cache 5000 \
  -cert-ttl 168h
```

---

## Troubleshooting

### Issue: Certificate Warnings on HTTPS

**Symptom**: Browser shows "Your connection is not private" or curl fails with certificate error

**Cause**: Root CA not installed in client trust store

**Solution**:
1. Verify root CA exists: `ls ~/.gosniffer/ca-cert.pem`
2. Re-install root CA following Step 1 in HTTPS section
3. Restart browser or clear SSL cache
4. Test: `curl -x http://localhost:8080 https://example.com` (should succeed)

### Issue: "Connection refused" when using proxy

**Symptom**: `curl: (7) Failed to connect to localhost port 8080: Connection refused`

**Cause**: GoSniffer not running or listening on wrong port

**Solution**:
1. Verify GoSniffer is running: `ps aux | grep gosniffer`
2. Check listen address: Look for "Proxy ready" message with correct port
3. Start proxy: `./bin/gosniffer -addr :8080`

### Issue: Headers not being injected

**Symptom**: `X-Proxied-By` header missing in upstream requests

**Cause**: Request not going through proxy, or implementation bug

**Solution**:
1. Verify proxy is configured: `echo $http_proxy` (should show `http://localhost:8080`)
2. Test with explicit proxy flag: `curl -x http://localhost:8080 http://httpbin.org/headers`
3. Check GoSniffer logs for request interception

### Issue: Slow performance / high latency

**Symptom**: Requests taking significantly longer through proxy

**Cause**: Certificate generation overhead, or network bottleneck

**Solution**:
1. Check certificate cache hit rate (logs show "Certificate generated" vs "Certificate cached")
2. Run benchmarks: `go test ./tests/benchmarks/... -bench=.`
3. Profile with pprof: `go test -cpuprofile=cpu.prof -bench=BenchmarkProxyHTTPS`

### Issue: Memory leak / high memory usage

**Symptom**: GoSniffer memory usage grows unbounded

**Cause**: Certificate cache not evicting, or goroutine leak

**Solution**:
1. Check certificate cache size (should cap at `-max-cache` value)
2. Run with race detector: `go test ./... -race`
3. Profile memory: `go test -memprofile=mem.prof`
4. Check goroutine count: Use pprof to inspect goroutine profiles

---

## Example Test Scenarios

### Scenario 1: HTTP + HTTPS Mixed Traffic

```bash
# Start proxy
./bin/gosniffer

# Generate mixed traffic
for i in {1..10}; do
  curl -x http://localhost:8080 http://httpbin.org/get &
  curl -x http://localhost:8080 https://httpbin.org/get &
done
wait
```

**Expected Output**: 20 log entries with alternating HTTP/HTTPS requests, all status 200

### Scenario 2: Certificate Caching Verification

```bash
# First request (certificate generated)
curl -x http://localhost:8080 https://example.com

# Second request (certificate cached - faster)
curl -x http://localhost:8080 https://example.com
```

**GoSniffer Logs**:
```
[CERT] Generated certificate for example.com (fingerprint: abc123...)
[2025-11-23 14:45:00] example.com - 200
[2025-11-23 14:45:05] example.com - 200  # No cert generation log
```

### Scenario 3: Concurrent Connection Load Test

```bash
# Generate 100 concurrent requests
seq 1 100 | xargs -P 100 -I {} curl -x http://localhost:8080 -s http://httpbin.org/get -o /dev/null
```

**Expected**: All 100 requests succeed, no race conditions (test with `go test -race`)

---

## Next Steps

Once quickstart testing is complete:

1. **Run full test suite**: `go test ./... -v -race`
2. **Run benchmarks**: `go test ./tests/benchmarks/... -bench=. -benchmem`
3. **Review constitution compliance**: Check that all principles are satisfied (see `plan.md` Constitution Check)
4. **Generate tasks**: Run `/speckit.tasks` to create detailed implementation task breakdown
5. **Begin implementation**: Follow tasks.md in priority order (P1 → P2 → P3)

---

## Security Reminders

⚠️ **Root CA Private Key**: File `~/.gosniffer/ca-key.pem` is SENSITIVE
- Contains private key that can sign certificates
- Protect with `chmod 600 ~/.gosniffer/ca-key.pem`
- Do NOT share or commit to version control

⚠️ **Trust Store Modification**: Installing root CA grants GoSniffer ability to intercept ALL HTTPS traffic
- Only install CA on machines you control
- Remove CA when no longer needed: `sudo update-ca-certificates --fresh` (Linux)

⚠️ **Use Cases**: GoSniffer is intended for:
- Local development and debugging
- Security research and penetration testing (authorized)
- Educational purposes (understanding MITM proxies)

Do NOT use GoSniffer for:
- Intercepting traffic on networks you don't own
- Bypassing security controls without authorization
- Monitoring other users without consent
