package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/yourusername/go-mitmproxy/pkg/ca"
	"github.com/yourusername/go-mitmproxy/pkg/logger"
)

const (
	// TLS handshake timeout
	tlsHandshakeTimeout = 10 * time.Second

	// Upstream connection timeout
	upstreamDialTimeout = 15 * time.Second
)

// MITMHandler handles HTTPS CONNECT requests with TLS interception
// Implements T031-T045: Full HTTPS MITM functionality
type MITMHandler struct {
	ca        *ca.CA
	certCache *ca.CertificateCache
	logger    *logger.Logger
}

// NewMITMHandler creates a new MITM handler
func NewMITMHandler(rootCA *ca.CA, certCache *ca.CertificateCache, log *logger.Logger) *MITMHandler {
	return &MITMHandler{
		ca:        rootCA,
		certCache: certCache,
		logger:    log,
	}
}

// HandleCONNECT handles HTTPS CONNECT requests and performs TLS MITM
// Implements:
// - T031: CONNECT method detection
// - T032: Connection hijacking
// - T033: "200 Connection Established" response
// - T034: Client TLS handshake
// - T035: Upstream TLS connection
// - T042: Certificate generation error handling
// - T043: TLS handshake error handling
// - T044: Certificate cache integration
// - T045: Logger integration
func (m *MITMHandler) HandleCONNECT(w http.ResponseWriter, r *http.Request) {
	// T031: Extract hostname from CONNECT request
	// CONNECT request format: "CONNECT example.com:443 HTTP/1.1"
	hostname := r.Host
	if hostname == "" {
		m.logger.LogError("CONNECT request missing host", fmt.Errorf("empty Host header"))
		http.Error(w, "Bad Request: missing host", http.StatusBadRequest)
		return
	}

	// Extract hostname without port for certificate generation
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		// If no port, use hostname as-is
		host = hostname
	}

	// T032: Hijack the connection to get raw TCP socket
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		m.logger.LogError("hijacking not supported", fmt.Errorf("ResponseWriter does not support hijacking"))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		m.logger.LogError(fmt.Sprintf("failed to hijack connection for %s", hostname), err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// T033: Send "200 Connection Established" response
	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := clientConn.Write([]byte(response)); err != nil {
		m.logger.LogError(fmt.Sprintf("failed to send CONNECT response for %s", hostname), err)
		return
	}

	// T044: Get or generate certificate (with cache integration)
	cert := m.certCache.Get(host)
	if cert == nil {
		// Certificate not in cache, generate new one
		// T042: Error handling for certificate generation (abort on failure per SR-007)
		cert, err = m.ca.GenerateCertificate(host, "rsa")
		if err != nil {
			m.logger.LogError(fmt.Sprintf("certificate generation failed for %s", host), err)
			// SR-007: MUST abort on certificate generation failure, no insecure fallback
			return
		}

		// Cache the generated certificate
		m.certCache.Put(host, cert)
	}

	// T036: TLS configuration (TLS 1.2 minimum, TLS 1.3 preferred)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert.TLSCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	// T034: Perform TLS handshake with client using generated certificate
	// T043: Error handling for TLS handshake failures
	clientTLS := tls.Server(clientConn, tlsConfig)
	clientTLS.SetDeadline(time.Now().Add(tlsHandshakeTimeout))

	if err := clientTLS.Handshake(); err != nil {
		m.logger.LogError(fmt.Sprintf("client TLS handshake failed for %s", host), err)
		// SR-007: MUST abort on TLS handshake failure
		return
	}

	// Clear deadline after successful handshake
	clientTLS.SetDeadline(time.Time{})

	// T035: Establish upstream TLS connection
	upstreamTLSConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		// Certificate verification enabled by default (validates upstream server)
	}

	dialer := &net.Dialer{
		Timeout: upstreamDialTimeout,
	}

	upstreamConn, err := tls.DialWithDialer(dialer, "tcp", hostname, upstreamTLSConfig)
	if err != nil {
		m.logger.LogError(fmt.Sprintf("upstream TLS connection failed for %s", hostname), err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	// Now we have two TLS connections:
	// - clientTLS: encrypted connection to client (decrypted by us)
	// - upstreamConn: encrypted connection to upstream server
	// We can now read/modify HTTP traffic in plaintext

	// T037: Parse decrypted HTTP request from client TLS connection
	// T038: Inject custom header for HTTPS requests
	// T039: Forward request to upstream TLS connection
	// T040: Read response and extract status code
	// T041: Relay response to client TLS connection
	// T045: Integrate logger for HTTPS request logging

	m.proxyHTTPSTraffic(clientTLS, upstreamConn, host)
}

// proxyHTTPSTraffic handles the bidirectional proxy of decrypted HTTPS traffic
// Implements T037-T041, T045
func (m *MITMHandler) proxyHTTPSTraffic(clientConn *tls.Conn, upstreamConn *tls.Conn, hostname string) {
	// T037: Read HTTP request from decrypted client connection
	clientReader := bufio.NewReader(clientConn)

	// Parse HTTP request
	req, err := http.ReadRequest(clientReader)
	if err != nil {
		m.logger.LogError(fmt.Sprintf("failed to read HTTPS request from client for %s", hostname), err)
		return
	}

	// DEBUG: Log request details
	contentLength := req.ContentLength
	m.logger.LogInfo(fmt.Sprintf("[DEBUG] %s %s %s (Content-Length: %d)",
		req.Method, hostname, req.URL.Path, contentLength))

	// Check if this is a WebSocket upgrade request
	if isWebSocketUpgrade(req) {
		m.logger.LogInfo(fmt.Sprintf("[DEBUG] WebSocket upgrade detected for %s, creating tunnel", hostname))
		m.handleWebSocketUpgrade(clientConn, upstreamConn, req, hostname)
		return
	}

	// T038: Inject custom header (same as HTTP interception)
	req.Header.Set(ProxyHeaderName, ProxyHeaderValue)

	// Remove hop-by-hop headers
	removeHopByHopHeaders(req.Header)

	// Ensure request URL is properly formatted for upstream
	// For HTTPS, the request URI is typically relative (e.g., "/path")
	req.RequestURI = ""
	req.URL.Scheme = "https"
	req.URL.Host = hostname

	// Set longer timeout for large request bodies (uploads)
	// Default Go http timeout is too short for large file uploads
	clientConn.SetWriteDeadline(time.Time{}) // No write deadline on client
	upstreamConn.SetWriteDeadline(time.Time{}) // No write deadline on upstream
	upstreamConn.SetReadDeadline(time.Time{})  // No read deadline on upstream

	// T039: Write request to upstream TLS connection
	// Use httputil.DumpRequestOut for proper body handling (includes body streaming)
	m.logger.LogInfo(fmt.Sprintf("[DEBUG] Dumping request for %s (method: %s, content-length: %d)",
		hostname, req.Method, req.ContentLength))

	reqDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		m.logger.LogError(fmt.Sprintf("failed to dump request for %s", hostname), err)
		return
	}

	m.logger.LogInfo(fmt.Sprintf("[DEBUG] Dumped %d bytes, writing to upstream %s", len(reqDump), hostname))

	// Write the complete request (headers + body) to upstream
	written, err := upstreamConn.Write(reqDump)
	if err != nil {
		m.logger.LogError(fmt.Sprintf("failed to write request to upstream for %s (wrote %d/%d bytes)",
			hostname, written, len(reqDump)), err)
		return
	}

	m.logger.LogInfo(fmt.Sprintf("[DEBUG] Successfully wrote %d bytes to upstream %s, waiting for response",
		written, hostname))

	// T040: Read response from upstream and extract status code
	m.logger.LogInfo(fmt.Sprintf("[DEBUG] Reading response from upstream %s", hostname))

	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		m.logger.LogError(fmt.Sprintf("failed to read response from upstream for %s (after writing %d bytes)",
			hostname, written), err)
		return
	}
	defer resp.Body.Close()

	m.logger.LogInfo(fmt.Sprintf("[DEBUG] Got response %d from upstream %s (content-length: %d)",
		resp.StatusCode, hostname, resp.ContentLength))

	// T045: Log HTTPS request (hostname and status code)
	m.logger.LogRequest(hostname, resp.StatusCode)

	// T041: Relay response to client TLS connection
	// Clear write deadline to allow large response bodies
	clientConn.SetWriteDeadline(time.Time{})
	if err := resp.Write(clientConn); err != nil {
		// Check if error is due to client closing connection (expected for some cases)
		if strings.Contains(err.Error(), "broken pipe") ||
		   strings.Contains(err.Error(), "connection reset") ||
		   strings.Contains(err.Error(), "wsasend") {
			// Client closed connection - this is normal, don't log as error
			return
		}
		m.logger.LogError(fmt.Sprintf("failed to write response to client for %s", hostname), err)
		return
	}

	// Handle additional requests on the same connection (HTTP keep-alive)
	// This is a simplified implementation - production code would need a full bidirectional relay
	m.handleKeepAlive(clientConn, upstreamConn, clientReader, hostname)
}

// handleKeepAlive handles multiple HTTP requests on the same TLS connection
func (m *MITMHandler) handleKeepAlive(clientConn *tls.Conn, upstreamConn *tls.Conn, clientReader *bufio.Reader, hostname string) {
	// Set a short read deadline to detect if client wants to send more requests
	clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))

	for {
		// Try to read next request
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			// Connection closed or no more requests
			if err != io.EOF && !strings.Contains(err.Error(), "timeout") {
				m.logger.LogError(fmt.Sprintf("error reading keep-alive request for %s", hostname), err)
			}
			return
		}

		// Clear deadline for request processing
		clientConn.SetReadDeadline(time.Time{})

		// DEBUG: Log keep-alive request
		m.logger.LogInfo(fmt.Sprintf("[DEBUG] Keep-alive: %s %s %s (Content-Length: %d)",
			req.Method, hostname, req.URL.Path, req.ContentLength))

		// Inject header and clean up request
		req.Header.Set(ProxyHeaderName, ProxyHeaderValue)
		removeHopByHopHeaders(req.Header)
		req.RequestURI = ""
		req.URL.Scheme = "https"
		req.URL.Host = hostname

		// Clear timeouts for large uploads
		clientConn.SetWriteDeadline(time.Time{})
		upstreamConn.SetWriteDeadline(time.Time{})
		upstreamConn.SetReadDeadline(time.Time{})

		// Forward request with proper body handling
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			m.logger.LogError(fmt.Sprintf("failed to dump keep-alive request for %s", hostname), err)
			return
		}

		m.logger.LogInfo(fmt.Sprintf("[DEBUG] Keep-alive: Writing %d bytes to upstream %s", len(reqDump), hostname))

		written, err := upstreamConn.Write(reqDump)
		if err != nil {
			m.logger.LogError(fmt.Sprintf("failed to forward keep-alive request for %s (wrote %d/%d bytes)",
				hostname, written, len(reqDump)), err)
			return
		}

		// Read response
		upstreamReader := bufio.NewReader(upstreamConn)
		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			m.logger.LogError(fmt.Sprintf("failed to read keep-alive response for %s", hostname), err)
			return
		}

		// Log request
		m.logger.LogRequest(hostname, resp.StatusCode)

		// Relay response with cleared deadline
		clientConn.SetWriteDeadline(time.Time{})
		if err := resp.Write(clientConn); err != nil {
			resp.Body.Close()
			// Don't log client-initiated disconnections as errors
			if !strings.Contains(err.Error(), "broken pipe") &&
			   !strings.Contains(err.Error(), "connection reset") &&
			   !strings.Contains(err.Error(), "wsasend") {
				m.logger.LogError(fmt.Sprintf("failed to relay keep-alive response for %s", hostname), err)
			}
			return
		}
		resp.Body.Close()

		// Set deadline for next request
		clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	}
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade
func isWebSocketUpgrade(req *http.Request) bool {
	return req.Header.Get("Upgrade") == "websocket" &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

// handleWebSocketUpgrade handles WebSocket upgrade requests by creating a bidirectional tunnel
func (m *MITMHandler) handleWebSocketUpgrade(clientConn *tls.Conn, upstreamConn *tls.Conn, req *http.Request, hostname string) {
	// Forward the upgrade request to upstream
	if err := req.Write(upstreamConn); err != nil {
		m.logger.LogError(fmt.Sprintf("failed to send WebSocket upgrade request to %s", hostname), err)
		return
	}

	m.logger.LogInfo(fmt.Sprintf("[DEBUG] Sent WebSocket upgrade request to %s, waiting for 101 response", hostname))

	// Read the upgrade response
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		m.logger.LogError(fmt.Sprintf("failed to read WebSocket upgrade response from %s", hostname), err)
		return
	}

	m.logger.LogInfo(fmt.Sprintf("[DEBUG] Got WebSocket upgrade response %d from %s", resp.StatusCode, hostname))

	// Check if upgrade was successful
	if resp.StatusCode != http.StatusSwitchingProtocols {
		m.logger.LogError(fmt.Sprintf("WebSocket upgrade failed for %s, got status %d", hostname, resp.StatusCode), nil)
		// Forward the error response to client
		resp.Write(clientConn)
		return
	}

	// Forward the 101 response to client
	if err := resp.Write(clientConn); err != nil {
		m.logger.LogError(fmt.Sprintf("failed to send WebSocket upgrade response to client for %s", hostname), err)
		return
	}

	m.logger.LogInfo(fmt.Sprintf("[DEBUG] WebSocket tunnel established for %s, starting bidirectional relay", hostname))
	m.logger.LogRequest(hostname, resp.StatusCode)

	// Now create a bidirectional tunnel for WebSocket frames
	// Clear all deadlines for long-lived WebSocket connection
	clientConn.SetDeadline(time.Time{})
	upstreamConn.SetDeadline(time.Time{})

	// Create bidirectional copy
	done := make(chan struct{}, 2)

	// Client -> Upstream
	go func() {
		io.Copy(upstreamConn, clientConn)
		done <- struct{}{}
	}()

	// Upstream -> Client
	go func() {
		io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()

	// Wait for either direction to complete
	<-done
	m.logger.LogInfo(fmt.Sprintf("[DEBUG] WebSocket tunnel closed for %s", hostname))
}
