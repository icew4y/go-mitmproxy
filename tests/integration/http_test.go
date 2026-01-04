package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yourusername/go-mitmproxy/pkg/logger"
	"github.com/yourusername/go-mitmproxy/pkg/proxy"
)

// TestHTTPInterception tests basic HTTP interception functionality (User Story 1)
// Verifies: FR-002, FR-006, FR-007
func TestHTTPInterception(t *testing.T) {
	// Create mock upstream server
	receivedHeader := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if custom header was injected
		receivedHeader = r.Header.Get("X-Proxied-By")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer upstream.Close()

	// Create HTTP-only proxy
	log := logger.NewLogger()
	proxyServer := proxy.NewProxyServer("127.0.0.1:18100", log)

	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Proxy error: %v", err)
		}
	}()
	defer proxyServer.Shutdown(1 * time.Second)

	time.Sleep(100 * time.Millisecond)

	// Create client configured to use proxy
	proxyURL, _ := url.Parse("http://127.0.0.1:18100")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Make HTTP request through proxy
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "test response" {
		t.Errorf("Expected 'test response', got '%s'", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify custom header was injected (FR-007)
	if receivedHeader != "GoSniffer" {
		t.Errorf("Expected X-Proxied-By header 'GoSniffer', got '%s'", receivedHeader)
	}
}

// TestHTTPMethods tests different HTTP methods
func TestHTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			// Create mock upstream
			receivedMethod := ""
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			// Create proxy
			log := logger.NewLogger()
			proxyServer := proxy.NewProxyServer(fmt.Sprintf("127.0.0.1:%d", 18101+len(method)), log)

			go proxyServer.Start()
			defer proxyServer.Shutdown(1 * time.Second)

			time.Sleep(100 * time.Millisecond)

			proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", 18101+len(method)))
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
				Timeout: 5 * time.Second,
			}

			// Make request with specific method
			req, _ := http.NewRequest(method, upstream.URL, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s request failed: %v", method, err)
			}
			resp.Body.Close()

			if receivedMethod != method {
				t.Errorf("Expected method %s, got %s", method, receivedMethod)
			}
		})
	}
}

// TestHTTPWithRequestBody tests HTTP POST with request body
func TestHTTPWithRequestBody(t *testing.T) {
	// Create mock upstream
	receivedBody := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	// Create proxy
	log := logger.NewLogger()
	proxyServer := proxy.NewProxyServer("127.0.0.1:18110", log)

	go proxyServer.Start()
	defer proxyServer.Shutdown(1 * time.Second)

	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://127.0.0.1:18110")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Make POST with body
	testBody := "test request body"
	resp, err := client.Post(upstream.URL, "text/plain", strings.NewReader(testBody))
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	resp.Body.Close()

	if receivedBody != testBody {
		t.Errorf("Expected body '%s', got '%s'", testBody, receivedBody)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}
}

// TestHTTPWithResponseHeaders tests response header forwarding
func TestHTTPWithResponseHeaders(t *testing.T) {
	// Create mock upstream with custom headers
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "test-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	// Create proxy
	log := logger.NewLogger()
	proxyServer := proxy.NewProxyServer("127.0.0.1:18111", log)

	go proxyServer.Start()
	defer proxyServer.Shutdown(1 * time.Second)

	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://127.0.0.1:18111")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify headers were forwarded
	if resp.Header.Get("X-Custom-Header") != "test-value" {
		t.Errorf("Custom header not forwarded correctly")
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type header not forwarded correctly")
	}
}

// TestHTTPErrorHandling tests proxy error handling for upstream failures
func TestHTTPErrorHandling(t *testing.T) {
	// Create proxy
	log := logger.NewLogger()
	proxyServer := proxy.NewProxyServer("127.0.0.1:18112", log)

	go proxyServer.Start()
	defer proxyServer.Shutdown(1 * time.Second)

	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://127.0.0.1:18112")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Try to connect to non-existent upstream
	resp, err := client.Get("http://localhost:99999/nonexistent")
	if err == nil {
		resp.Body.Close()
		t.Fatal("Expected error for non-existent upstream, got success")
	}

	// Error is expected - verify it's a reasonable error
	if !strings.Contains(err.Error(), "dial tcp") && !strings.Contains(err.Error(), "connection refused") {
		t.Logf("Got expected error: %v", err)
	}
}

// TestHTTPConcurrentRequests tests handling multiple concurrent requests
func TestHTTPConcurrentRequests(t *testing.T) {
	// Create mock upstream
	requestCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		time.Sleep(10 * time.Millisecond) // Simulate processing
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Create proxy
	log := logger.NewLogger()
	proxyServer := proxy.NewProxyServer("127.0.0.1:18113", log)

	go proxyServer.Start()
	defer proxyServer.Shutdown(2 * time.Second)

	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://127.0.0.1:18113")

	// Make 10 concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
				Timeout: 5 * time.Second,
			}

			resp, err := client.Get(upstream.URL)
			if err == nil {
				resp.Body.Close()
				done <- true
			} else {
				t.Logf("Concurrent request failed: %v", err)
				done <- false
			}
		}()
	}

	// Wait for all requests to complete
	successCount := 0
	for i := 0; i < 10; i++ {
		if <-done {
			successCount++
		}
	}

	if successCount < 8 {
		t.Errorf("Expected at least 8/10 concurrent requests to succeed, got %d", successCount)
	}
}
