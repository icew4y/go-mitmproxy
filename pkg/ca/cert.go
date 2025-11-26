package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"
)

// CertificateBundle represents a generated leaf certificate with its private key
type CertificateBundle struct {
	PrivateKey  interface{}        // *rsa.PrivateKey or *ecdsa.PrivateKey
	Certificate *x509.Certificate
	TLSCert     *tls.Certificate   // Ready-to-use tls.Certificate
	Hostname    string
	CreatedAt   time.Time
}

// GenerateCertificate creates a new leaf certificate for the specified hostname
// signed by the provided CA. Supports both RSA and ECDSA key types.
// Implements:
// - T022: Leaf certificate generation
// - T023: SAN (Subject Alternative Name) support
// - T024: Certificate fingerprint logging
// - T025: Key strength validation
func (ca *CA) GenerateCertificate(hostname string, keyType string) (*CertificateBundle, error) {
	// Generate private key for leaf certificate
	var privateKey interface{}
	var err error

	switch keyType {
	case "rsa":
		// Generate 2048-bit RSA key (per constitution SR-001)
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA private key for %s: %w", hostname, err)
		}
	case "ecdsa":
		// Generate P-256 ECDSA key (per constitution SR-001)
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA private key for %s: %w", hostname, err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s (must be 'rsa' or 'ecdsa')", keyType)
	}

	// T025: Validate leaf certificate key strength
	if err := validateKeyStrength(privateKey); err != nil {
		return nil, fmt.Errorf("leaf certificate key strength validation failed for %s: %w", hostname, err)
	}

	// Generate cryptographically random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number for %s: %w", hostname, err)
	}

	// Create leaf certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GoSniffer Leaf Certificate"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour), // 90 days validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,

		// T023: SAN (Subject Alternative Name) support for hostname validation
		// Required for modern browsers - Common Name alone is deprecated
		DNSNames: []string{hostname},
	}

	// Extract public key from private key
	var publicKey interface{}
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &key.PublicKey
	default:
		return nil, fmt.Errorf("unsupported private key type for %s", hostname)
	}

	// Sign the certificate with the CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate for %s: %w", hostname, err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate for %s: %w", hostname, err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	var keyPEM []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key for %s: %w", hostname, err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
	}

	// Create tls.Certificate for immediate use
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate for %s: %w", hostname, err)
	}

	bundle := &CertificateBundle{
		PrivateKey:  privateKey,
		Certificate: cert,
		TLSCert:     &tlsCert,
		Hostname:    hostname,
		CreatedAt:   time.Now(),
	}

	// T024: Log certificate generation with fingerprint (SR-004)
	fingerprint := calculateFingerprint(certDER)
	log.Printf("[CERT] Generated leaf certificate for %s (fingerprint: %s)\n", hostname, fingerprint)

	return bundle, nil
}
