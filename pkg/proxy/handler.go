package proxy

import (
	"fmt"
	"io"
	"net/http"

	"github.com/yourusername/go-mitmproxy/pkg/logger"
)

const (
	// Custom header injected into all proxied requests (FR-007)
	ProxyHeaderName  = "X-Proxied-By"
	ProxyHeaderValue = "GoSniffer"
)

// HandleHTTPRequest handles HTTP proxy requests (not HTTPS CONNECT)
// Implements:
// - FR-002: Intercept HTTP requests and forward to upstream
// - FR-006: Log hostname and status code
// - FR-007: Inject custom header
// Constitution Principle II: Rigorous error handling for all network operations
func HandleHTTPRequest(w http.ResponseWriter, r *http.Request, log *logger.Logger) {
	// Extract hostname from request
	hostname := getHostname(r)

	// Note: CONNECT method is handled by MITMHandler at proxy level
	// This function only handles regular HTTP methods (GET, POST, etc.)

	// Inject custom header into request (FR-007)
	r.Header.Set(ProxyHeaderName, ProxyHeaderValue)

	// Remove hop-by-hop headers (per HTTP proxy spec RFC 2616)
	removeHopByHopHeaders(r.Header)

	// Forward request to upstream server using http.DefaultTransport
	statusCode, err := forwardRequest(w, r)
	if err != nil {
		// Log error with context (constitution Principle II)
		log.LogError(fmt.Sprintf("forwarding request to %s", hostname), err)
		return
	}

	// Log successful request with hostname and status code (FR-006)
	log.LogRequest(hostname, statusCode)
}

// forwardRequest forwards the HTTP request to the upstream server and relays the response
// Returns the HTTP status code and any error encountered
func forwardRequest(w http.ResponseWriter, r *http.Request) (int, error) {
	// Create HTTP client with default transport
	client := &http.Client{
		// Disable automatic redirect following (proxy should forward as-is)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// Timeout for upstream connection
		Timeout: 30 * 0, // No timeout, rely on server timeouts
	}

	// Create new request to upstream (copying original request)
	upstreamReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		// Wrap error with context (constitution Principle II)
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return http.StatusInternalServerError, fmt.Errorf("failed to create upstream request: %w", err)
	}

	// Copy headers from original request
	upstreamReq.Header = r.Header.Clone()

	// Perform upstream request
	resp, err := client.Do(upstreamReq)
	if err != nil {
		// Distinguish between different error types (constitution Principle II)
		// Network errors, timeouts, DNS failures -> 502 Bad Gateway
		http.Error(w, "Bad Gateway: upstream server unreachable", http.StatusBadGateway)
		return http.StatusBadGateway, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	// Copy response headers to client
	copyHeaders(w.Header(), resp.Header)

	// Write status code to client
	w.WriteHeader(resp.StatusCode)

	// Copy response body to client
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		// Log error but don't return it (response already started)
		return resp.StatusCode, fmt.Errorf("failed to copy response body: %w", err)
	}

	return resp.StatusCode, nil
}

// getHostname extracts the hostname from the HTTP request
// Handles both absolute and relative URIs
func getHostname(r *http.Request) string {
	// For proxy requests, r.URL.Host contains the target hostname
	if r.URL.Host != "" {
		return r.URL.Host
	}

	// Fallback to Host header
	return r.Host
}

// removeHopByHopHeaders removes headers that should not be forwarded
// Per RFC 2616 Section 13.5.1: Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE, Trailers, Transfer-Encoding, Upgrade
func removeHopByHopHeaders(h http.Header) {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}

// copyHeaders copies HTTP headers from source to destination
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
