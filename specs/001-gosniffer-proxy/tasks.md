# Tasks: GoSniffer Forward Proxy

**Input**: Design documents from `specs/001-gosniffer-proxy/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Tests are OPTIONAL for this feature - only included where explicitly beneficial for constitution compliance (concurrency, security, performance validation).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3, WS for WebSocket)
- Include exact file paths in descriptions

## Task Summary

- **Total Tasks**: 155 (47 completed, 108 remaining)
- **Phase 1 (Setup)**: T001-T004 (4 tasks) ✓ Complete
- **Phase 2 (Foundational)**: T005-T011 (7 tasks) ✓ Complete
- **Phase 3 (HTTP MVP)**: T012-T021 (10 tasks) ✓ Complete
- **Phase 4 (HTTPS MITM)**: T022-T047 (26 tasks) ✓ Complete
- **Phase 5 (Graceful Shutdown)**: T048-T058 (11 tasks)
- **Phase 6 (Polish)**: T059-T090 (32 tasks)
- **Phase 7 (WebSocket MITM)**: T091-T117 (27 tasks) - Optional
- **Phase 8 (TLS Fingerprinting)**: T118-T155 (38 tasks) - Optional

## Path Conventions

- **Single project**: `cmd/`, `pkg/`, `tests/` at repository root
- Paths shown below follow standard Go project layout from plan.md

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [x] T001 Initialize Go module with `go mod init github.com/yourusername/go-mitmproxy`
- [x] T002 [P] Create directory structure per plan.md: cmd/gosniffer/, pkg/ca/, pkg/proxy/, pkg/logger/, tests/
- [x] T003 [P] Create go.mod and verify zero third-party dependencies (stdlib only)
- [x] T004 [P] Create README.md with project description and build instructions

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Root CA Module (Foundation for US2)

- [x] T005 [P] Implement Root CA generation in pkg/ca/ca.go (GenerateCA function)
- [x] T006 [P] Implement Root CA persistence (SaveToPEM, LoadFromPEM) in pkg/ca/ca.go
- [x] T007 Implement SHA-256 fingerprint calculation and logging in pkg/ca/ca.go
- [x] T008 Add validation for CA key strength (2048-bit RSA / P-256 ECDSA) in pkg/ca/ca.go

### Logging Module (Foundation for US1, US2)

- [x] T009 Implement request logger structure in pkg/logger/logger.go
- [x] T010 Implement log formatting (timestamp, hostname, status code) in pkg/logger/logger.go
- [x] T011 Add log sanitization to prevent injection attacks in pkg/logger/logger.go

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Basic HTTP Traffic Interception (Priority: P1) 🎯 MVP

**Goal**: Intercept HTTP requests, inject custom header, log hostname and status code

**Independent Test**: Configure client with proxy, make HTTP requests to public sites, verify console logs show hostname/status and upstream receives `X-Proxied-By: GoSniffer` header

### Implementation for User Story 1

- [x] T012 [P] [US1] Create proxy server struct in pkg/proxy/proxy.go (ProxyServer type)
- [x] T013 [P] [US1] Implement HTTP proxy listener in pkg/proxy/proxy.go (Start method)
- [x] T014 [US1] Implement HTTP request handler in pkg/proxy/handler.go (ServeHTTP method)
- [x] T015 [US1] Implement header injection logic (`X-Proxied-By: GoSniffer`) in pkg/proxy/handler.go
- [x] T016 [US1] Implement upstream request forwarding using http.DefaultTransport in pkg/proxy/handler.go
- [x] T017 [US1] Implement response relay (status code extraction + logging) in pkg/proxy/handler.go
- [x] T018 [US1] Add error handling for upstream failures (502/504 responses) in pkg/proxy/handler.go
- [x] T019 [US1] Integrate logger for hostname/status output in pkg/proxy/handler.go
- [x] T020 [US1] Implement CLI in cmd/gosniffer/main.go (flag parsing: -addr, -ca-cert, -ca-key)
- [x] T021 [US1] Wire up HTTP proxy server startup in cmd/gosniffer/main.go

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently - HTTP interception with header injection and logging works

---

## Phase 4: User Story 2 - HTTPS Traffic Interception with TLS MITM (Priority: P2)

**Goal**: Intercept HTTPS requests using MITM with dynamically generated certificates, inject custom header, log hostname/status

**Independent Test**: Install root CA, configure client for HTTPS proxy, access https://google.com, verify logs show "google.com - 200" and no certificate errors

### Certificate Generation Module

- [x] T022 [P] [US2] Implement leaf certificate generation in pkg/ca/cert.go (GenerateCertificate function)
- [x] T023 [P] [US2] Add SAN (Subject Alternative Name) support for hostname validation in pkg/ca/cert.go
- [x] T024 [P] [US2] Implement certificate fingerprint logging (SHA-256) in pkg/ca/cert.go
- [x] T025 [US2] Add validation for leaf certificate key strength in pkg/ca/cert.go

### Certificate Cache Module

- [x] T026 [P] [US2] Implement certificate cache structure (map + mutex) in pkg/ca/cache.go
- [x] T027 [P] [US2] Implement cache Get operation (thread-safe) in pkg/ca/cache.go
- [x] T028 [P] [US2] Implement cache Put operation with race condition prevention in pkg/ca/cache.go
- [x] T029 [US2] Implement LRU eviction policy (max 1000 entries) in pkg/ca/cache.go
- [x] T030 [US2] Implement TTL cleanup goroutine (30-day expiration) in pkg/ca/cache.go

### HTTPS MITM Implementation

- [x] T031 [P] [US2] Implement CONNECT method detection in pkg/proxy/proxy.go
- [x] T032 [US2] Implement connection hijacking (http.Hijacker) in pkg/proxy/mitm.go
- [x] T033 [US2] Implement "200 Connection Established" response in pkg/proxy/mitm.go
- [x] T034 [US2] Implement client TLS handshake with generated certificate in pkg/proxy/mitm.go
- [x] T035 [US2] Implement upstream TLS connection with certificate validation in pkg/proxy/mitm.go
- [x] T036 [US2] Implement TLS configuration (TLS 1.2 min, 1.3 preferred) in pkg/proxy/mitm.go
- [x] T037 [US2] Implement decrypted HTTP request parsing from client TLS connection in pkg/proxy/mitm.go
- [x] T038 [US2] Implement header injection for HTTPS requests in pkg/proxy/mitm.go
- [x] T039 [US2] Implement request forwarding to upstream TLS connection in pkg/proxy/mitm.go
- [x] T040 [US2] Implement response reading and status code extraction in pkg/proxy/mitm.go
- [x] T041 [US2] Implement response relay to client TLS connection in pkg/proxy/mitm.go
- [x] T042 [US2] Add error handling for certificate generation failures (SR-007: abort, no fallback) in pkg/proxy/mitm.go
- [x] T043 [US2] Add error handling for TLS handshake failures in pkg/proxy/mitm.go
- [x] T044 [US2] Integrate certificate cache with MITM logic in pkg/proxy/mitm.go
- [x] T045 [US2] Integrate logger for HTTPS request logging in pkg/proxy/mitm.go

### CLI Integration for HTTPS

- [x] T046 [US2] Add root CA initialization to cmd/gosniffer/main.go (generate or load CA at startup)
- [x] T047 [US2] Wire up CONNECT handler for HTTPS MITM in cmd/gosniffer/main.go

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently - HTTP and HTTPS interception with header injection and logging

---

## Phase 5: User Story 3 - Graceful Shutdown (Priority: P3)

**Goal**: Clean shutdown on SIGINT/SIGTERM, drain active connections within 30 seconds, exit cleanly

**Independent Test**: Start GoSniffer, initiate slow HTTP/HTTPS requests, send SIGINT, verify active requests complete while new requests rejected, followed by clean exit

### Implementation for User Story 3

- [ ] T048 [P] [US3] Implement shutdown coordinator structure in pkg/proxy/shutdown.go
- [ ] T049 [P] [US3] Implement connection tracking (map of active connections) in pkg/proxy/shutdown.go
- [ ] T050 [US3] Implement context-based cancellation propagation in pkg/proxy/shutdown.go
- [ ] T051 [US3] Implement shutdown signal (stop accepting new connections) in pkg/proxy/shutdown.go
- [ ] T052 [US3] Implement connection draining with WaitGroup in pkg/proxy/shutdown.go
- [ ] T053 [US3] Implement graceful shutdown timeout (30 seconds) in pkg/proxy/shutdown.go
- [ ] T054 [US3] Implement forceful connection close after timeout in pkg/proxy/shutdown.go
- [ ] T055 [US3] Register SIGINT/SIGTERM signal handlers in cmd/gosniffer/main.go
- [ ] T056 [US3] Wire up shutdown coordinator with signal handlers in cmd/gosniffer/main.go
- [ ] T057 [US3] Integrate connection tracking into HTTP handler in pkg/proxy/handler.go
- [ ] T058 [US3] Integrate connection tracking into HTTPS MITM handler in pkg/proxy/mitm.go

**Checkpoint**: All user stories should now be independently functional - HTTP, HTTPS, and graceful shutdown

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

### Concurrency & Performance *(constitution principle I & IV)*

- [ ] T059 [P] Add race detection test script: `go test ./... -race`
- [ ] T060 [P] Create connection setup benchmark in tests/benchmarks/proxy_bench_test.go
- [ ] T061 [P] Create HTTP relay benchmark in tests/benchmarks/proxy_bench_test.go
- [ ] T062 [P] Create HTTPS MITM handshake benchmark in tests/benchmarks/proxy_bench_test.go
- [ ] T063 [P] Create certificate generation benchmark in tests/benchmarks/cert_bench_test.go
- [ ] T064 Verify <5ms p99 latency overhead (run benchmarks, analyze results)
- [ ] T065 Verify <100ms certificate generation (run benchmarks, analyze results)
- [ ] T066 [P] Profile with pprof (CPU and memory) to identify optimization opportunities
- [ ] T067 Implement buffer pools for hot paths if allocations are high (based on profiling)
- [ ] T068 Verify context cancellation propagates correctly through goroutine trees

### Security Hardening *(constitution principle III)*

- [ ] T069 [P] Audit all certificate generation for crypto/rand usage in pkg/ca/
- [ ] T070 [P] Verify private key strength requirements (2048-bit RSA / P-256 ECDSA) in pkg/ca/
- [ ] T071 [P] Verify certificate operation logging with fingerprints in pkg/ca/
- [ ] T072 Verify certificate cache bounds (max 1000 entries, 30-day TTL) in pkg/ca/cache.go
- [ ] T073 [P] Verify TLS validation checks (hostname, expiration, chain of trust) in pkg/proxy/mitm.go
- [ ] T074 [P] Verify TLS version enforcement (TLS 1.2 min, 1.3 preferred) in pkg/proxy/mitm.go
- [ ] T075 Run govulncheck to scan for vulnerabilities: `go run golang.org/x/vuln/cmd/govulncheck ./...`
- [ ] T076 [P] Audit log output to ensure no sensitive data (private keys, tokens, bodies) in pkg/logger/

### Error Handling *(constitution principle II)*

- [ ] T077 [P] Review all network operations for explicit error checks in pkg/proxy/
- [ ] T078 [P] Ensure errors are wrapped with context (`fmt.Errorf` with `%w`) in pkg/proxy/
- [ ] T079 [P] Verify cleanup with `defer` statements for all resource allocations in pkg/proxy/
- [ ] T080 Document error conditions in public API functions (add godoc comments) in pkg/

### Integration Testing *(optional - for validation)*

- [ ] T081 [P] Create HTTP interception integration test in tests/integration/http_test.go
- [ ] T082 [P] Create HTTPS MITM integration test in tests/integration/https_test.go
- [ ] T083 [P] Create graceful shutdown integration test in tests/integration/shutdown_test.go
- [ ] T084 Run all integration tests with race detector: `go test ./tests/integration/... -race`

### General Polish

- [ ] T085 [P] Add godoc comments to all exported functions/types in pkg/
- [ ] T086 [P] Run go fmt on all files: `go fmt ./...`
- [ ] T087 [P] Run go vet for static analysis: `go vet ./...`
- [ ] T088 [P] Run golint or staticcheck for code quality: `staticcheck ./...`
- [ ] T089 Update README.md with installation and usage instructions from quickstart.md
- [ ] T090 Create example configuration files (if needed)

---

## Phase 7: WebSocket MITM Inspection (Optional Enhancement)

**Purpose**: Deep inspection of WebSocket traffic for MITM analysis

**Goal**: Parse WebSocket frames to inspect, log, and optionally modify WebSocket messages (text/binary) flowing through the proxy

**Note**: Currently WebSocket connections use transparent tunneling (works but no inspection). This phase adds full WebSocket protocol parsing for message-level MITM.

**Independent Test**: Start proxy, establish WebSocket connection through it (e.g., Speedtest.net upload), verify logs show individual WebSocket frames/messages with opcodes, sizes, and payloads

### WebSocket Frame Parser

- [ ] T091 [P] [WS] Create WebSocket frame structure in pkg/websocket/frame.go (opcode, fin, mask, payload length, masking key)
- [ ] T092 [P] [WS] Implement WebSocket frame parser (ReadFrame function) in pkg/websocket/frame.go
- [ ] T093 [P] [WS] Implement WebSocket frame writer (WriteFrame function) in pkg/websocket/frame.go
- [ ] T094 [WS] Implement payload unmasking for client->server frames in pkg/websocket/frame.go
- [ ] T095 [WS] Implement payload masking for server->client frames (optional - usually not masked) in pkg/websocket/frame.go
- [ ] T096 [WS] Add frame validation (check reserved bits, validate opcode, length limits) in pkg/websocket/frame.go

### WebSocket Message Handler

- [ ] T097 [P] [WS] Implement message fragmentation handling (reassemble fragmented frames) in pkg/websocket/message.go
- [ ] T098 [P] [WS] Implement TEXT message decoder (UTF-8 validation) in pkg/websocket/message.go
- [ ] T099 [P] [WS] Implement BINARY message decoder in pkg/websocket/message.go
- [ ] T100 [WS] Implement control frame handling (PING, PONG, CLOSE) in pkg/websocket/message.go
- [ ] T101 [WS] Add close frame reason code parsing in pkg/websocket/message.go

### WebSocket MITM Integration

- [ ] T102 [P] [WS] Create WebSocket inspector structure in pkg/proxy/ws_mitm.go
- [ ] T103 [WS] Implement client->server message inspection loop in pkg/proxy/ws_mitm.go
- [ ] T104 [WS] Implement server->client message inspection loop in pkg/proxy/ws_mitm.go
- [ ] T105 [WS] Add WebSocket message logging (opcode, size, preview of payload) in pkg/proxy/ws_mitm.go
- [ ] T106 [WS] Integrate WebSocket inspector into handleWebSocketUpgrade in pkg/proxy/mitm.go
- [ ] T107 [WS] Add configuration flag --enable-ws-inspection (default: false) in cmd/gosniffer/main.go
- [ ] T108 [WS] Add WebSocket frame metrics (frame count, bytes transferred, message types) in pkg/proxy/ws_mitm.go

### WebSocket Message Modification (Advanced - Optional)

- [ ] T109 [P] [WS] Implement message modification interface in pkg/websocket/modifier.go
- [ ] T110 [WS] Add example TEXT message modifier (e.g., redact sensitive data) in pkg/websocket/modifier.go
- [ ] T111 [WS] Add example BINARY message modifier in pkg/websocket/modifier.go
- [ ] T112 [WS] Integrate message modifiers into WebSocket inspector in pkg/proxy/ws_mitm.go

### WebSocket Testing & Validation

- [ ] T113 [P] [WS] Create WebSocket frame parser unit tests in pkg/websocket/frame_test.go
- [ ] T114 [P] [WS] Create WebSocket message handler tests in pkg/websocket/message_test.go
- [ ] T115 [WS] Create WebSocket MITM integration test (end-to-end with real WebSocket server) in tests/integration/websocket_test.go
- [ ] T116 [WS] Test with various WebSocket implementations (browser WebSocket API, wscat, etc.)
- [ ] T117 [WS] Verify constitution compliance: goroutine per connection, proper error handling, performance

**Checkpoint**: WebSocket inspection fully functional - can parse, log, and optionally modify WebSocket messages in both directions

**Performance Target**: <1ms overhead per WebSocket frame, <10ms for message reassembly

**Note**: This phase is **optional** and should only be implemented if deep WebSocket inspection is required. For many use cases (like Speedtest.net), transparent tunneling (current implementation) is sufficient.

---

## Phase 8: TLS Fingerprint Spoofing (Priority: P4 - Optional)

**Purpose**: Mimic browser TLS fingerprints to bypass TLS fingerprinting-based detection

**Goal**: Proxy can impersonate Chrome/Firefox/Safari TLS Client Hello to avoid bot detection and fingerprinting systems

**Note**: This phase requires `utls` third-party library (constitution Principle V exception - see plan.md for justification)

**Independent Test**: Configure `--tls-fingerprint chrome`, connect through proxy to ja3er.com or tls.peet.ws, verify JA3 hash matches Chrome 120+ fingerprint

### Fingerprint Profiles & Research

- [ ] T118 [P] [US4] Research current browser TLS fingerprints (Chrome 120+, Firefox 121+, Safari 17+) - cipher suites, curves, extensions, versions
- [ ] T119 [P] [US4] Create fingerprint profile structure in pkg/tls/fingerprint.go (cipher suites, curves, extensions, TLS versions)
- [ ] T120 [P] [US4] Implement Chrome 120+ fingerprint profile with accurate JA3 parameters
- [ ] T121 [P] [US4] Implement Firefox 121+ fingerprint profile with accurate JA3 parameters
- [ ] T122 [P] [US4] Implement Safari 17+ fingerprint profile with accurate JA3 parameters
- [ ] T123 [US4] Add custom fingerprint loader (read from JSON config file)
- [ ] T124 [US4] Add fingerprint validation (ensure cipher/curve compatibility, TLS 1.2+ minimum per SR-010)

### utls Library Integration

- [ ] T125 [US4] Add utls dependency to go.mod: github.com/refraction-networking/utls
- [ ] T126 [P] [US4] Create utls wrapper in pkg/tls/utls_wrapper.go (convert fingerprint profiles to utls.ClientHelloID)
- [ ] T127 [US4] Implement fingerprint-to-utls-config converter (map profiles to utls parameters)
- [ ] T128 [US4] Add utls.UConn creation helper function (wraps net.Conn with utls fingerprint)
- [ ] T129 [US4] Implement TLS handshake with fingerprinted client in pkg/tls/utls_wrapper.go

### MITM Integration

- [ ] T130 [US4] Modify pkg/proxy/mitm.go upstream TLS connection to use fingerprinted handshake
- [ ] T131 [US4] Add fingerprint selection logic (choose profile based on config)
- [ ] T132 [US4] Replace standard tls.Dial with utls.UConn for upstream connections when fingerprinting enabled
- [ ] T133 [US4] Add fallback handling for fingerprint-incompatible servers (log error, fail gracefully per SR-009)
- [ ] T134 [US4] Add fingerprint logging (log which profile is being used per connection)

### CLI & Configuration

- [ ] T135 [US4] Add --tls-fingerprint flag in cmd/gosniffer/main.go (values: none|chrome|firefox|safari|custom)
- [ ] T136 [US4] Add --tls-fingerprint-config flag (path to custom JSON fingerprint config)
- [ ] T137 [US4] Wire up fingerprint initialization in main.go (load profile, validate, pass to MITM handler)
- [ ] T138 [US4] Add fingerprint info to startup logs (which profile is active, validation results)
- [ ] T139 [US4] Add fingerprint selection to proxy configuration structure

### Testing & Validation

- [ ] T140 [P] [US4] Create fingerprint validation tests in pkg/tls/fingerprint_test.go
- [ ] T141 [P] [US4] Create utls wrapper tests in pkg/tls/utls_wrapper_test.go
- [ ] T142 [US4] Test against ja3er.com - verify Chrome fingerprint matches
- [ ] T143 [US4] Test against ja3er.com - verify Firefox fingerprint matches
- [ ] T144 [US4] Test against ja3er.com - verify Safari fingerprint matches
- [ ] T145 [US4] Test against tls.peet.ws (alternative fingerprinting service)
- [ ] T146 [US4] Test with Cloudflare-protected site (known to use TLS fingerprinting)
- [ ] T147 [US4] Test with Akamai-protected site (bot detection via fingerprinting)
- [ ] T148 [US4] Verify custom fingerprint JSON loading and validation
- [ ] T149 [US4] Test fallback behavior with incompatible fingerprint/server combination
- [ ] T150 [US4] Run govulncheck on utls dependency: `go run golang.org/x/vuln/cmd/govulncheck ./...`

### Documentation

- [ ] T151 [P] [US4] Document utls dependency in README.md with security implications
- [ ] T152 [P] [US4] Create example custom fingerprint JSON config file
- [ ] T153 [US4] Add fingerprint spoofing usage guide to README.md
- [ ] T154 [US4] Document JA3 testing procedure with ja3er.com/tls.peet.ws
- [ ] T155 [US4] Update constitution.md with Principle V exception justification

**Checkpoint**: TLS fingerprint spoofing fully functional - proxy successfully mimics browser TLS handshakes and bypasses fingerprinting-based detection

**Performance Target**: <5ms overhead for fingerprint application per connection

**Constitution Note**: This phase introduces `utls` third-party dependency (exception to Principle V). Justification documented in plan.md - TLS fingerprinting is impossible with Go stdlib alone. Mitigation: feature flag (opt-in), isolated to pkg/tls/, regular security audits.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3, 4, 5)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3)
- **Polish (Phase 6)**: Depends on all desired user stories being complete
- **WebSocket MITM (Phase 7)**: Optional - Depends on Phase 4 (HTTPS MITM) completion, can proceed in parallel with Phase 5/6
- **TLS Fingerprinting (Phase 8)**: Optional - Depends on Phase 4 (HTTPS MITM) completion, can proceed in parallel with Phase 5/6/7

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - Depends on Root CA module but independent of US1
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) - Independent of US1/US2 (adds shutdown coordination)

### Within Each User Story

- **US1 (HTTP)**: T012-T013 (proxy setup) → T014-T019 (handler + logging) → T020-T021 (CLI integration)
- **US2 (HTTPS)**: T022-T025 (cert generation) || T026-T030 (cache) → T031-T045 (MITM) → T046-T047 (CLI integration)
- **US3 (Shutdown)**: T048-T054 (shutdown coordinator) → T055-T058 (signal handlers + integration)

### Parallel Opportunities

- **Setup (Phase 1)**: All tasks (T001-T004) can run in parallel
- **Foundational (Phase 2)**: T005-T008 (CA module) || T009-T011 (logger module) can run in parallel
- **US1**: T012-T013 can run in parallel
- **US2**: T022-T025 (cert generation) || T026-T030 (cache) can run in parallel before MITM implementation
- **US3**: T048-T049 can run in parallel
- **Polish**: Most audit/verification tasks (marked [P]) can run in parallel
- **WebSocket (Phase 7)**: T091-T096 (frame parser) || T097-T101 (message handler) can run in parallel, followed by integration
- **TLS Fingerprinting (Phase 8)**: T118-T122 (browser profiles) || T126-T129 (utls wrapper) can run in parallel, followed by integration

---

## Parallel Example: User Story 2 (HTTPS MITM)

```bash
# Launch certificate generation and cache modules together:
Task T022: "Implement leaf certificate generation in pkg/ca/cert.go"
Task T023: "Add SAN support for hostname validation in pkg/ca/cert.go"
Task T024: "Implement certificate fingerprint logging in pkg/ca/cert.go"
Task T025: "Add validation for leaf certificate key strength in pkg/ca/cert.go"

# In parallel:
Task T026: "Implement certificate cache structure in pkg/ca/cache.go"
Task T027: "Implement cache Get operation in pkg/ca/cache.go"
Task T028: "Implement cache Put operation with race prevention in pkg/ca/cache.go"

# After both complete:
Task T029: "Implement LRU eviction policy in pkg/ca/cache.go"
Task T030: "Implement TTL cleanup goroutine in pkg/ca/cache.go"
Task T031-T045: "MITM implementation tasks..."
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001-T004)
2. Complete Phase 2: Foundational (T005-T011) - CRITICAL
3. Complete Phase 3: User Story 1 (T012-T021)
4. **STOP and VALIDATE**: Test User Story 1 independently
   - Configure client: `export http_proxy=http://localhost:8080`
   - Test: `curl -x http://localhost:8080 http://httpbin.org/headers`
   - Verify console logs: `[timestamp] httpbin.org - 200`
   - Verify header injection: `"X-Proxied-By": "GoSniffer"` in response
5. Deploy/demo if ready - **Working HTTP proxy!**

### Incremental Delivery

1. Complete Setup + Foundational (T001-T011) → Foundation ready
2. Add User Story 1 (T012-T021) → Test independently → Deploy/Demo (**MVP - HTTP proxy**)
3. Add User Story 2 (T022-T047) → Test independently → Deploy/Demo (**HTTP + HTTPS proxy**)
4. Add User Story 3 (T048-T058) → Test independently → Deploy/Demo (**Full feature set**)
5. Add Polish (T059-T090) → Final validation → Production-ready
6. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together (T001-T011)
2. Once Foundational is done:
   - **Developer A**: User Story 1 (T012-T021) - HTTP interception
   - **Developer B**: User Story 2 (T022-T047) - HTTPS MITM (can start cert/cache in parallel with US1)
   - **Developer C**: User Story 3 (T048-T058) - Graceful shutdown (can start in parallel)
3. Stories complete and integrate independently
4. Team collaborates on Polish (T059-T090)

---

## Notes

- **[P] tasks** = different files, no dependencies on incomplete work
- **[Story] label** maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Tests are OPTIONAL - included only for critical validation (concurrency, security, performance)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- **Constitution compliance**: All tasks align with go-mitmproxy constitution principles (concurrency idioms, rigorous error handling, secure TLS, performance, simplicity)

### Testing Notes

- **Unit tests**: Optional, but recommended for CA module (cert generation validation)
- **Integration tests**: Optional, but recommended for end-to-end validation of each user story
- **Benchmarks**: REQUIRED per constitution Principle IV (performance measurement)
- **Race detector**: REQUIRED per constitution Principle I (go test -race)
- If implementing tests: Write tests FIRST, ensure they FAIL before implementation (TDD)

### Critical Paths Requiring Extra Attention

1. **Certificate generation race conditions** (T028, T044): Ensure thread-safe cache operations
2. **TLS handshake error handling** (T042, T043): MUST abort on errors, no insecure fallback
3. **Context cancellation** (T050, T068): Ensure proper cleanup across goroutine trees
4. **Error wrapping** (T078): All errors must use `fmt.Errorf` with `%w` for context
5. **Performance validation** (T064, T065): Must meet <5ms p99 latency, <100ms cert generation targets
