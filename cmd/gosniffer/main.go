package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yourusername/go-mitmproxy/pkg/ca"
	"github.com/yourusername/go-mitmproxy/pkg/logger"
	"github.com/yourusername/go-mitmproxy/pkg/proxy"
)

var (
	// Command-line flags (FR-010)
	addr            = flag.String("addr", ":8080", "Listen address for proxy server")
	caCertPath      = flag.String("ca-cert", getDefaultCAPath("ca-cert.pem"), "Path to root CA certificate file")
	caKeyPath       = flag.String("ca-key", getDefaultCAPath("ca-key.pem"), "Path to root CA private key file")
	shutdownTimeout = flag.Duration("shutdown-timeout", 30*time.Second, "Graceful shutdown timeout")
	enableHTTPS     = flag.Bool("enable-https", true, "Enable HTTPS MITM interception (default: true)")
	caKeyType       = flag.String("ca-key-type", "rsa", "CA key type: 'rsa' or 'ecdsa' (default: rsa)")
)

func main() {
	// Parse command-line flags
	flag.Parse()

	// Create logger
	requestLogger := logger.NewLogger()

	requestLogger.LogInfo(fmt.Sprintf("GoSniffer v1.0 - Forward Proxy with MITM Interception"))
	requestLogger.LogInfo(fmt.Sprintf("Listen address: %s", *addr))

	// T046: Initialize root CA (generate or load)
	var proxyServer *proxy.ProxyServer
	var certCache *ca.CertificateCache

	if *enableHTTPS {
		rootCA, err := initializeCA(*caCertPath, *caKeyPath, *caKeyType, requestLogger)
		if err != nil {
			log.Fatalf("Failed to initialize CA: %v", err)
		}

		// Create certificate cache
		certCache = ca.NewCertificateCache()
		requestLogger.LogInfo("Certificate cache initialized")

		// T047: Create MITM handler and proxy server with HTTPS support
		mitmHandler := proxy.NewMITMHandler(rootCA, certCache, requestLogger)
		proxyServer = proxy.NewProxyServerWithMITM(*addr, requestLogger, mitmHandler)
		requestLogger.LogInfo("HTTPS MITM interception enabled")
	} else {
		// Create HTTP-only proxy server
		proxyServer = proxy.NewProxyServer(*addr, requestLogger)
		requestLogger.LogInfo("HTTP-only mode (HTTPS MITM disabled)")
	}

	// Setup signal handlers for graceful shutdown (FR-008)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start proxy server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := proxyServer.Start(); err != nil {
			errChan <- fmt.Errorf("proxy server error: %w", err)
		}
	}()

	requestLogger.LogInfo("Proxy ready. Press Ctrl+C to stop.")

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		requestLogger.LogInfo(fmt.Sprintf("Received signal %v, shutting down gracefully...", sig))

		// Graceful shutdown (FR-009)
		if err := proxyServer.Shutdown(*shutdownTimeout); err != nil {
			log.Fatalf("Shutdown error: %v", err)
		}

	case err := <-errChan:
		log.Fatalf("Proxy server error: %v", err)
	}

	requestLogger.LogInfo("GoSniffer stopped")

	// Stop certificate cache cleanup goroutine if it was started
	if certCache != nil {
		certCache.Stop()
	}
}

// initializeCA loads an existing CA or generates a new one
func initializeCA(certPath, keyPath, keyType string, logger *logger.Logger) (*ca.CA, error) {
	// Check if CA files exist
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	if certErr == nil && keyErr == nil {
		// CA files exist, load them
		logger.LogInfo(fmt.Sprintf("Loading existing CA from %s", certPath))
		rootCA, err := ca.LoadFromPEM(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA: %w", err)
		}
		return rootCA, nil
	}

	// CA files don't exist, generate new CA
	logger.LogInfo(fmt.Sprintf("Generating new %s CA certificate...", keyType))
	rootCA, err := ca.GenerateCA(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	// Save CA to disk
	if err := rootCA.SaveToPEM(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("failed to save CA: %w", err)
	}

	logger.LogInfo(fmt.Sprintf("CA certificate saved to %s", certPath))
	logger.LogInfo("IMPORTANT: Install the root CA certificate on your client devices to avoid certificate warnings")

	return rootCA, nil
}

// getDefaultCAPath returns the default path for CA files
// Default location: ~/.gosniffer/
func getDefaultCAPath(filename string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if home directory cannot be determined
		return filename
	}

	return filepath.Join(homeDir, ".gosniffer", filename)
}
