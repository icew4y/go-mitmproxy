package benchmarks

import (
	"testing"

	"github.com/yourusername/go-mitmproxy/pkg/ca"
)

// BenchmarkCertificateGenerationRSA benchmarks RSA certificate generation
// Target: <100ms per certificate (T065)
func BenchmarkCertificateGenerationRSA(b *testing.B) {
	// Generate root CA once
	rootCA, err := ca.GenerateCA("rsa")
	if err != nil {
		b.Fatalf("Failed to generate CA: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rootCA.GenerateCertificate("example.com", "rsa")
		if err != nil {
			b.Fatalf("Failed to generate certificate: %v", err)
		}
	}
}

// BenchmarkCertificateGenerationECDSA benchmarks ECDSA certificate generation
// Target: <100ms per certificate (T065)
func BenchmarkCertificateGenerationECDSA(b *testing.B) {
	// Generate root CA once
	rootCA, err := ca.GenerateCA("ecdsa")
	if err != nil {
		b.Fatalf("Failed to generate CA: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rootCA.GenerateCertificate("example.com", "ecdsa")
		if err != nil {
			b.Fatalf("Failed to generate certificate: %v", err)
		}
	}
}

// BenchmarkCACacheGet benchmarks certificate cache retrieval
func BenchmarkCACacheGet(b *testing.B) {
	rootCA, err := ca.GenerateCA("rsa")
	if err != nil {
		b.Fatalf("Failed to generate CA: %v", err)
	}

	cache := ca.NewCertificateCache()
	defer cache.Stop()

	// Pre-populate cache with a certificate
	cert, err := rootCA.GenerateCertificate("example.com", "rsa")
	if err != nil {
		b.Fatalf("Failed to generate certificate: %v", err)
	}
	cache.Put("example.com", cert)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("example.com")
	}
}

// BenchmarkCACachePut benchmarks certificate cache storage
func BenchmarkCACachePut(b *testing.B) {
	rootCA, err := ca.GenerateCA("rsa")
	if err != nil {
		b.Fatalf("Failed to generate CA: %v", err)
	}

	cache := ca.NewCertificateCache()
	defer cache.Stop()

	// Generate certificate once
	cert, err := rootCA.GenerateCertificate("example.com", "rsa")
	if err != nil {
		b.Fatalf("Failed to generate certificate: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Put("example.com", cert)
	}
}

// BenchmarkRootCAGeneration benchmarks root CA generation
func BenchmarkRootCAGenerationRSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := ca.GenerateCA("rsa")
		if err != nil {
			b.Fatalf("Failed to generate CA: %v", err)
		}
	}
}

// BenchmarkRootCAGenerationECDSA benchmarks ECDSA root CA generation
func BenchmarkRootCAGenerationECDSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := ca.GenerateCA("ecdsa")
		if err != nil {
			b.Fatalf("Failed to generate CA: %v", err)
		}
	}
}
