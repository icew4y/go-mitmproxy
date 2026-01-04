package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yourusername/go-mitmproxy/pkg/logger"
)

// ShutdownCoordinator manages graceful shutdown of the proxy server
// Tracks active connections and ensures clean shutdown within timeout
// Implements Tasks T048-T054 for User Story 3 (Graceful Shutdown)
type ShutdownCoordinator struct {
	// Connection tracking
	connections map[string]net.Conn
	connMu      sync.RWMutex

	// WaitGroup for tracking active connection handlers
	wg sync.WaitGroup

	// Context for cancellation propagation
	ctx    context.Context
	cancel context.CancelFunc

	// Shutdown state
	shuttingDown bool
	shutdownMu   sync.RWMutex

	logger *logger.Logger
}

// NewShutdownCoordinator creates a new shutdown coordinator
func NewShutdownCoordinator(logger *logger.Logger) *ShutdownCoordinator {
	ctx, cancel := context.WithCancel(context.Background())
	return &ShutdownCoordinator{
		connections: make(map[string]net.Conn),
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger,
	}
}

// Context returns the coordinator's context for cancellation propagation (T050)
func (sc *ShutdownCoordinator) Context() context.Context {
	return sc.ctx
}

// IsShuttingDown returns true if shutdown has been initiated (T051)
func (sc *ShutdownCoordinator) IsShuttingDown() bool {
	sc.shutdownMu.RLock()
	defer sc.shutdownMu.RUnlock()
	return sc.shuttingDown
}

// TrackConnection registers a new connection for tracking (T049)
// Returns a unique connection ID for later removal
func (sc *ShutdownCoordinator) TrackConnection(conn net.Conn) string {
	sc.connMu.Lock()
	defer sc.connMu.Unlock()

	// Generate unique connection ID
	connID := fmt.Sprintf("%s->%s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	sc.connections[connID] = conn

	// Increment WaitGroup for this connection (T052)
	sc.wg.Add(1)

	return connID
}

// UntrackConnection removes a connection from tracking (T049)
// Should be called when connection is closed
func (sc *ShutdownCoordinator) UntrackConnection(connID string) {
	sc.connMu.Lock()
	defer sc.connMu.Unlock()

	delete(sc.connections, connID)

	// Decrement WaitGroup for this connection (T052)
	sc.wg.Done()
}

// Shutdown initiates graceful shutdown with timeout (T053)
// Stops accepting new connections, drains existing ones, and forcefully closes after timeout (T054)
func (sc *ShutdownCoordinator) Shutdown(timeout time.Duration) error {
	// Mark as shutting down (T051)
	sc.shutdownMu.Lock()
	sc.shuttingDown = true
	sc.shutdownMu.Unlock()

	sc.logger.LogInfo(fmt.Sprintf("Shutdown initiated. Draining connections (timeout: %v)...", timeout))

	// T050: Cancel context to signal all goroutines to stop
	sc.cancel()

	// T052: Wait for all connections to close gracefully (with timeout)
	done := make(chan struct{})
	go func() {
		sc.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All connections closed gracefully
		sc.logger.LogInfo("All connections closed gracefully")
		return nil

	case <-time.After(timeout):
		// T053: Timeout reached
		sc.logger.LogInfo(fmt.Sprintf("Shutdown timeout (%v) reached. Forcefully closing remaining connections...", timeout))

		// T054: Forcefully close all remaining connections
		sc.connMu.Lock()
		remainingCount := len(sc.connections)
		for connID, conn := range sc.connections {
			sc.logger.LogInfo(fmt.Sprintf("Force closing connection: %s", connID))
			conn.Close()
		}
		sc.connMu.Unlock()

		sc.logger.LogInfo(fmt.Sprintf("Forcefully closed %d remaining connections", remainingCount))

		// Wait a bit for WaitGroup to drain after forceful close
		select {
		case <-done:
			return nil
		case <-time.After(1 * time.Second):
			return fmt.Errorf("some connections did not close after forceful shutdown")
		}
	}
}

// GetActiveConnectionCount returns the number of currently tracked connections
// Useful for monitoring and logging
func (sc *ShutdownCoordinator) GetActiveConnectionCount() int {
	sc.connMu.RLock()
	defer sc.connMu.RUnlock()
	return len(sc.connections)
}
