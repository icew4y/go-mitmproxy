package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/yourusername/go-mitmproxy/pkg/logger"
)

// ProxyServer represents an HTTP/HTTPS proxy server
type ProxyServer struct {
	addr                string
	server              *http.Server
	logger              *logger.Logger
	mitmHandler         *MITMHandler // HTTPS MITM handler (nil if HTTPS not enabled)
	shutdownCoordinator *ShutdownCoordinator
	mu                  sync.Mutex
	running             bool
}

// NewProxyServer creates a new proxy server instance (HTTP only)
func NewProxyServer(addr string, logger *logger.Logger) *ProxyServer {
	return &ProxyServer{
		addr:                addr,
		logger:              logger,
		shutdownCoordinator: NewShutdownCoordinator(logger),
	}
}

// NewProxyServerWithMITM creates a new proxy server with HTTPS MITM support
func NewProxyServerWithMITM(addr string, logger *logger.Logger, mitmHandler *MITMHandler) *ProxyServer {
	sc := NewShutdownCoordinator(logger)

	// Wire up shutdown coordinator with MITM handler for connection tracking
	mitmHandler.SetShutdownCoordinator(sc)

	return &ProxyServer{
		addr:                addr,
		logger:              logger,
		mitmHandler:         mitmHandler,
		shutdownCoordinator: sc,
	}
}

// Start starts the HTTP proxy server and begins listening for connections
// Implements constitution Principle I: dedicated goroutine per connection
func (p *ProxyServer) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("proxy server is already running")
	}
	p.running = true
	p.mu.Unlock()

	// Create HTTP server with custom handler
	// Note: We use http.HandlerFunc directly instead of ServeMux because
	// ServeMux is designed for web servers and doesn't handle CONNECT requests properly.
	// CONNECT requests have URIs like "httpbin.org:443" not "/" which causes 301 redirects.
	p.server = &http.Server{
		Addr:    p.addr,
		Handler: http.HandlerFunc(p.handleHTTP),
		// Connection timeouts per constitution error handling
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		// Each connection gets its own goroutine (Go default behavior)
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return ctx
		},
	}

	p.logger.LogInfo(fmt.Sprintf("GoSniffer proxy starting on %s", p.addr))

	// Start server in main thread (blocking)
	if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("proxy server failed: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the proxy server
// Waits for active connections to complete within timeout
func (p *ProxyServer) Shutdown(timeout time.Duration) error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return fmt.Errorf("proxy server is not running")
	}
	p.mu.Unlock()

	p.logger.LogInfo("Initiating graceful shutdown...")

	// Create context with timeout for HTTP server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Shutdown HTTP server (stops accepting new connections)
	go func() {
		if err := p.server.Shutdown(ctx); err != nil {
			p.logger.LogError("HTTP server shutdown", err)
		}
	}()

	// Use shutdown coordinator to drain connections
	if err := p.shutdownCoordinator.Shutdown(timeout); err != nil {
		p.logger.LogError("shutdown coordinator", err)
		// Continue shutdown even if error
	}

	p.mu.Lock()
	p.running = false
	p.mu.Unlock()

	p.logger.LogInfo("Proxy server shutdown complete")
	return nil
}

// handleHTTP handles all HTTP/HTTPS proxy requests
// Routes CONNECT requests to MITM handler, regular HTTP to HandleHTTPRequest
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if this is a CONNECT request (HTTPS MITM)
	if r.Method == http.MethodConnect {
		// Route to MITM handler if available
		if p.mitmHandler != nil {
			p.mitmHandler.HandleCONNECT(w, r)
			return
		}

		// If MITM not configured, return 501 Not Implemented
		http.Error(w, "HTTPS MITM not configured", http.StatusNotImplemented)
		p.logger.LogError("CONNECT method", fmt.Errorf("MITM handler not initialized"))
		return
	}

	// Handle regular HTTP requests
	HandleHTTPRequest(w, r, p.logger)
}
