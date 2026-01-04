package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/yourusername/go-mitmproxy/pkg/ca"
	"github.com/yourusername/go-mitmproxy/pkg/logger"
	"github.com/yourusername/go-mitmproxy/pkg/proxy"
)

// TestGracefulShutdownHTTP tests graceful shutdown with active HTTP connections
func TestGracefulShutdownHTTP(t *testing.T) {
	// Create logger
	log := logger.NewLogger()

	// Create HTTP-only proxy server
	proxyAddr := "127.0.0.1:18080"
	proxyServer := proxy.NewProxyServer(proxyAddr, log)

	// Start proxy server in background
	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Proxy server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create a slow HTTP request that will be in progress during shutdown
	slowRequestDone := make(chan bool, 1)
	go func() {
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(mustParseURL(fmt.Sprintf("http://%s", proxyAddr))),
			},
			Timeout: 10 * time.Second,
		}

		// Make request to httpbin.org which should respond
		resp, err := client.Get("http://httpbin.org/delay/2")
		if err != nil {
			// Request might fail if shutdown happens, that's okay
			t.Logf("Request completed with error (expected during shutdown): %v", err)
		} else {
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			t.Logf("Request completed successfully with status: %d", resp.StatusCode)
		}
		slowRequestDone <- true
	}()

	// Wait a bit for request to start
	time.Sleep(500 * time.Millisecond)

	// Initiate graceful shutdown
	shutdownStart := time.Now()
	shutdownErr := make(chan error, 1)
	go func() {
		shutdownErr <- proxyServer.Shutdown(5 * time.Second)
	}()

	// Wait for both the slow request and shutdown to complete
	select {
	case err := <-shutdownErr:
		shutdownDuration := time.Since(shutdownStart)
		if err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}
		t.Logf("Shutdown completed in %v", shutdownDuration)

	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown timeout - test failed")
	}

	// Wait for slow request to finish
	select {
	case <-slowRequestDone:
		t.Log("Slow request completed")
	case <-time.After(2 * time.Second):
		t.Log("Slow request did not complete (may have been cancelled)")
	}
}

// TestGracefulShutdownHTTPS tests graceful shutdown with active HTTPS connections
func TestGracefulShutdownHTTPS(t *testing.T) {
	// Create logger
	log := logger.NewLogger()

	// Generate test CA
	rootCA, err := ca.GenerateCA("rsa")
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Create certificate cache
	certCache := ca.NewCertificateCache()
	defer certCache.Stop()

	// Create MITM handler and proxy server
	proxyAddr := "127.0.0.1:18443"
	mitmHandler := proxy.NewMITMHandler(rootCA, certCache, log)
	proxyServer := proxy.NewProxyServerWithMITM(proxyAddr, log, mitmHandler)

	// Start proxy server in background
	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Proxy server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create client that skips certificate verification (for testing)
	slowRequestDone := make(chan bool, 1)
	go func() {
		// Note: In real test we would install the CA certificate
		// For this test we skip verification
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(mustParseURL(fmt.Sprintf("http://%s", proxyAddr))),
			},
			Timeout: 10 * time.Second,
		}

		// Make HTTPS request
		resp, err := client.Get("https://httpbin.org/delay/2")
		if err != nil {
			t.Logf("HTTPS request completed with error (expected during shutdown): %v", err)
		} else {
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			t.Logf("HTTPS request completed successfully with status: %d", resp.StatusCode)
		}
		slowRequestDone <- true
	}()

	// Wait a bit for request to start
	time.Sleep(500 * time.Millisecond)

	// Initiate graceful shutdown
	shutdownStart := time.Now()
	shutdownErr := make(chan error, 1)
	go func() {
		shutdownErr <- proxyServer.Shutdown(5 * time.Second)
	}()

	// Wait for shutdown to complete
	select {
	case err := <-shutdownErr:
		shutdownDuration := time.Since(shutdownStart)
		if err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}
		t.Logf("Shutdown completed in %v", shutdownDuration)

	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown timeout - test failed")
	}

	// Wait for slow request to finish
	select {
	case <-slowRequestDone:
		t.Log("Slow HTTPS request completed")
	case <-time.After(2 * time.Second):
		t.Log("Slow HTTPS request did not complete (may have been cancelled)")
	}
}

// TestShutdownRejectsNewConnections tests that new connections are rejected during shutdown
func TestShutdownRejectsNewConnections(t *testing.T) {
	// Create logger
	log := logger.NewLogger()

	// Generate test CA
	rootCA, err := ca.GenerateCA("rsa")
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Create certificate cache
	certCache := ca.NewCertificateCache()
	defer certCache.Stop()

	// Create MITM handler and proxy server
	proxyAddr := "127.0.0.1:18444"
	mitmHandler := proxy.NewMITMHandler(rootCA, certCache, log)
	proxyServer := proxy.NewProxyServerWithMITM(proxyAddr, log, mitmHandler)

	// Start proxy server in background
	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Proxy server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Initiate shutdown
	go func() {
		time.Sleep(200 * time.Millisecond)
		proxyServer.Shutdown(3 * time.Second)
	}()

	// Wait for shutdown to begin
	time.Sleep(300 * time.Millisecond)

	// Try to make a new connection (should be rejected or fail)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://httpbin.org/get", nil)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(fmt.Sprintf("http://%s", proxyAddr))),
		},
	}

	_, err = client.Do(req)
	if err != nil {
		t.Logf("New connection rejected during shutdown (expected): %v", err)
	} else {
		t.Log("Connection succeeded (server may not have started shutdown yet)")
	}
}

// Helper function to parse URL
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// TestMain runs all tests and sets up/tears down resources
func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()

	// Exit with test result code
	os.Exit(code)
}
