# GoSniffer - Forward Proxy with MITM TLS Interception

A command-line forward proxy written in Go that intercepts HTTP and HTTPS traffic, performs TLS man-in-the-middle interception using a self-signed root CA, and logs all requests with custom header injection.

## Features

- **HTTP Interception**: Forwards HTTP requests with custom header injection (`X-Proxied-By: GoSniffer`)
- **HTTPS MITM**: Intercepts HTTPS traffic using dynamically generated certificates signed by a root CA
- **Request Logging**: Logs hostname and response status code for every request
- **Graceful Shutdown**: Cleanly stops on SIGINT/SIGTERM, draining active connections
- **Zero Dependencies**: Built entirely with Go standard library

## Prerequisites

- Go 1.21 or later
- For HTTPS interception: Root CA must be installed in client's trust store

## Build

```bash
go build -o bin/gosniffer ./cmd/gosniffer
```

## Usage

### Basic Usage

```bash
./bin/gosniffer -addr :8080
```

### Command-Line Flags

- `-addr`: Listen address for proxy server (default: `:8080`)
- `-ca-cert`: Path to root CA certificate file (default: `~/.gosniffer/ca-cert.pem`)
- `-ca-key`: Path to root CA private key file (default: `~/.gosniffer/ca-key.pem`)
- `-shutdown-timeout`: Graceful shutdown timeout (default: `30s`)
- `-enable-https`: Enable HTTPS MITM interception (default: `true`)
- `-ca-key-type`: CA key type: 'rsa' or 'ecdsa' (default: `rsa`)

### HTTP Interception

1. Start GoSniffer:
   ```bash
   ./bin/gosniffer -addr :8080
   ```

2. Configure your client to use the proxy:
   ```bash
   export http_proxy=http://localhost:8080
   export https_proxy=http://localhost:8080
   ```

3. Make an HTTP request:
   ```bash
   curl -x http://localhost:8080 http://httpbin.org/headers
   ```

4. Verify in the response that `X-Proxied-By: GoSniffer` header is present

### HTTPS Interception

1. Start GoSniffer (will generate root CA on first run):
   ```bash
   ./bin/gosniffer -addr :8080
   ```

2. Install the root CA certificate into your client's trust store:

   **Linux (Ubuntu/Debian)**:
   ```bash
   sudo cp ~/.gosniffer/ca-cert.pem /usr/local/share/ca-certificates/gosniffer.crt
   sudo update-ca-certificates
   ```

   **macOS**:
   ```bash
   sudo security add-trusted-cert -d -r trustRoot \
     -k /Library/Keychains/System.keychain \
     ~/.gosniffer/ca-cert.pem
   ```

   **Windows** (PowerShell as Administrator):
   ```powershell
   Import-Certificate -FilePath "$env:USERPROFILE\.gosniffer\ca-cert.pem" -CertStoreLocation Cert:\LocalMachine\Root
   ```

3. Make an HTTPS request:
   ```bash
   curl -x http://localhost:8080 https://httpbin.org/headers
   ```

4. Verify no certificate errors occur and the custom header is present

## Performance

Benchmark results on Intel Core i9-14900K:

- **Certificate Generation:** ~34ms (RSA), ~0.11ms (ECDSA) - Well under 100ms target ✅
- **HTTPS MITM Handshake:** ~1.4ms per request ✅
- **Certificate Cache:** ~22ns (get/put operations)
- **Concurrent Requests:** Handles 100+ simultaneous connections

All benchmarks pass performance targets with zero race conditions detected.

## Architecture

GoSniffer follows standard Go project layout:

```
go-mitmproxy/
├── cmd/gosniffer/      # CLI entry point
├── pkg/
│   ├── ca/            # Certificate authority and generation
│   ├── proxy/         # HTTP/HTTPS proxy logic
│   └── logger/        # Request logging
└── tests/             # Tests and benchmarks
```

## Security Considerations

⚠️ **Warning**: GoSniffer performs man-in-the-middle interception of HTTPS traffic. Only use on networks and systems you own or have explicit authorization to monitor.

- Root CA private key is stored in `~/.gosniffer/ca-key.pem` (permissions: 600)
- Installing the root CA grants GoSniffer the ability to intercept ALL HTTPS traffic
- Remove the root CA from your trust store when no longer needed
- Do not share or commit the root CA private key

## Development

### Running Tests

```bash
# Unit tests
go test ./pkg/... -v

# Integration tests
go test ./tests/integration/... -v

# Race detection
go test ./... -race

# Benchmarks
go test ./tests/benchmarks/... -bench=. -benchmem
```

### Code Quality

```bash
# Format code
go fmt ./...

# Static analysis
go vet ./...

# Vulnerability scanning
go run golang.org/x/vuln/cmd/govulncheck ./...
```

## License

This project is for educational and authorized security testing purposes only.

## Constitution Compliance

GoSniffer adheres to strict development principles:

- **Go Concurrency Idioms**: Per-connection goroutines, channel-based communication, context cancellation
- **Rigorous Error Handling**: All network operations checked, errors wrapped with context
- **Secure TLS Interception**: crypto/rand for key generation, 2048-bit RSA minimum, certificate audit logging
- **Performance & Efficiency**: <5ms p99 latency overhead, benchmarks for critical paths
- **Simplicity & Maintainability**: Zero third-party dependencies, stdlib only, clear code structure

## Contributing

This is a learning/demonstration project. Contributions welcome for educational improvements.
