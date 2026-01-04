package ca

import (
	"container/list"
	"context"
	"log"
	"sync"
	"time"
)

const (
	// Maximum number of cached certificates (LRU eviction after this)
	MaxCacheSize = 1000

	// Certificate TTL (30 days per data model specification)
	CertificateTTL = 30 * 24 * time.Hour

	// TTL cleanup interval (check every hour)
	CleanupInterval = 1 * time.Hour
)

// CertificateCache provides thread-safe LRU cache for generated certificates
// Implements:
// - T026: Cache structure with map + mutex
// - T027: Thread-safe Get operation
// - T028: Thread-safe Put operation with race prevention
// - T029: LRU eviction policy (max 1000 entries)
// - T030: TTL cleanup goroutine (30-day expiration)
type CertificateCache struct {
	mu       sync.RWMutex           // Protects cache and lruList
	cache    map[string]*cacheEntry // hostname -> cache entry
	lruList  *list.List             // LRU tracking (most recent at back)
	maxSize  int                    // Maximum cache size
	ttl      time.Duration          // Certificate TTL
	stopChan chan struct{}          // Signal to stop cleanup goroutine
	wg       sync.WaitGroup         // Wait for cleanup goroutine
}

// cacheEntry wraps a certificate bundle with LRU tracking
type cacheEntry struct {
	bundle     *CertificateBundle
	lruElement *list.Element // Pointer to element in LRU list
}

// NewCertificateCache creates a new certificate cache and starts the TTL cleanup goroutine
func NewCertificateCache() *CertificateCache {
	cache := &CertificateCache{
		cache:    make(map[string]*cacheEntry),
		lruList:  list.New(),
		maxSize:  MaxCacheSize,
		ttl:      CertificateTTL,
		stopChan: make(chan struct{}),
	}

	// T030: Start TTL cleanup goroutine (constitution Principle I: dedicated goroutine)
	cache.wg.Add(1)
	go cache.cleanupExpired()

	return cache
}

// Get retrieves a certificate from the cache
// Returns nil if not found or expired
// T027: Thread-safe Get operation with read lock
func (c *CertificateCache) Get(hostname string) *CertificateBundle {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.cache[hostname]
	if !exists {
		return nil
	}

	// Check if certificate has expired (TTL check)
	if time.Since(entry.bundle.CreatedAt) > c.ttl {
		// Remove expired certificate
		c.removeLocked(hostname)
		return nil
	}

	// Update LRU: move to back (most recently used)
	c.lruList.MoveToBack(entry.lruElement)

	return entry.bundle
}

// Put adds a certificate to the cache
// T028: Thread-safe Put operation with race prevention
// T029: Implements LRU eviction when cache exceeds maxSize
func (c *CertificateCache) Put(hostname string, bundle *CertificateBundle) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if hostname already exists (race prevention)
	if entry, exists := c.cache[hostname]; exists {
		// Update existing entry and move to back
		entry.bundle = bundle
		c.lruList.MoveToBack(entry.lruElement)
		return
	}

	// T029: LRU eviction if cache is full
	if c.lruList.Len() >= c.maxSize {
		// Evict least recently used (front of list)
		oldest := c.lruList.Front()
		if oldest != nil {
			oldestHostname := oldest.Value.(string)
			c.removeLocked(oldestHostname)
			log.Printf("[CACHE] Evicted certificate for %s (LRU policy, cache size: %d)\n",
				oldestHostname, c.lruList.Len())
		}
	}

	// Add new entry to cache
	lruElement := c.lruList.PushBack(hostname)
	c.cache[hostname] = &cacheEntry{
		bundle:     bundle,
		lruElement: lruElement,
	}
}

// removeLocked removes a certificate from the cache (must hold lock)
func (c *CertificateCache) removeLocked(hostname string) {
	entry, exists := c.cache[hostname]
	if !exists {
		return
	}

	// Remove from LRU list
	c.lruList.Remove(entry.lruElement)

	// Remove from cache map
	delete(c.cache, hostname)
}

// Size returns the current cache size
func (c *CertificateCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Stop stops the TTL cleanup goroutine and waits for it to complete
func (c *CertificateCache) Stop() {
	close(c.stopChan)
	c.wg.Wait()
}

// cleanupExpired runs periodically to remove expired certificates
// T030: TTL cleanup goroutine (30-day expiration)
// Constitution Principle I: Uses dedicated goroutine with context cancellation
func (c *CertificateCache) cleanupExpired() {
	defer c.wg.Done()

	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.performCleanup()
		case <-c.stopChan:
			log.Println("[CACHE] Stopping TTL cleanup goroutine")
			return
		}
	}
}

// performCleanup removes all expired certificates from the cache
func (c *CertificateCache) performCleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	// Collect expired hostnames
	var expiredHostnames []string
	for hostname, entry := range c.cache {
		if now.Sub(entry.bundle.CreatedAt) > c.ttl {
			expiredHostnames = append(expiredHostnames, hostname)
		}
	}

	// Remove expired certificates
	for _, hostname := range expiredHostnames {
		c.removeLocked(hostname)
		expiredCount++
	}

	if expiredCount > 0 {
		log.Printf("[CACHE] Cleaned up %d expired certificates (cache size: %d)\n",
			expiredCount, len(c.cache))
	}
}

// StopWithContext stops the cleanup goroutine with a context timeout
func (c *CertificateCache) StopWithContext(ctx context.Context) error {
	close(c.stopChan)

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
