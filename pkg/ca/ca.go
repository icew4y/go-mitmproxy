package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA represents a Certificate Authority with its private key and certificate
type CA struct {
	PrivateKey  interface{}        // *rsa.PrivateKey or *ecdsa.PrivateKey
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

// GenerateCA creates a new self-signed root CA certificate
// Supports both RSA (2048-bit minimum) and ECDSA (P-256)
// Uses crypto/rand for cryptographically secure random generation
func GenerateCA(keyType string) (*CA, error) {
	var privateKey interface{}
	var err error

	// Generate private key based on type
	switch keyType {
	case "rsa":
		// Generate 2048-bit RSA key (minimum per constitution SR-001)
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
		}
	case "ecdsa":
		// Generate P-256 ECDSA key (per constitution SR-001)
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s (must be 'rsa' or 'ecdsa')", keyType)
	}

	// Validate key strength
	if err := validateKeyStrength(privateKey); err != nil {
		return nil, fmt.Errorf("key strength validation failed: %w", err)
	}

	// Generate cryptographically random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create CA certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GoSniffer Root CA"},
			CommonName:   "GoSniffer Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the certificate
	var publicKey interface{}
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &key.PublicKey
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

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
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
	}

	ca := &CA{
		PrivateKey:  privateKey,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}

	// Log certificate generation with fingerprint (SR-004)
	fingerprint := calculateFingerprint(certDER)
	log.Printf("[CERT] Generated root CA certificate (fingerprint: %s)\n", fingerprint)

	return ca, nil
}

// SaveToPEM saves the CA certificate and private key to PEM files
func (ca *CA) SaveToPEM(certPath, keyPath string) error {
	// Create directory if it doesn't exist
	certDir := filepath.Dir(certPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", certDir, err)
	}

	// Write certificate file (public, readable by all)
	if err := os.WriteFile(certPath, ca.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate to %s: %w", certPath, err)
	}

	// Write private key file (sensitive, owner read/write only)
	if err := os.WriteFile(keyPath, ca.KeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key to %s: %w", keyPath, err)
	}

	log.Printf("[CA] Saved certificate to %s and private key to %s\n", certPath, keyPath)
	return nil
}

// LoadFromPEM loads a CA certificate and private key from PEM files
func LoadFromPEM(certPath, keyPath string) (*CA, error) {
	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate from %s: %w", certPath, err)
	}

	// Read private key file
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key from %s: %w", keyPath, err)
	}

	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM certificate from %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM private key from %s", keyPath)
	}

	var privateKey interface{}
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
	case "PRIVATE KEY":
		// PKCS#8 format
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}

	// Validate key strength
	if err := validateKeyStrength(privateKey); err != nil {
		return nil, fmt.Errorf("loaded key does not meet strength requirements: %w", err)
	}

	ca := &CA{
		PrivateKey:  privateKey,
		Certificate: cert,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}

	// Log loaded certificate with fingerprint (SR-004)
	fingerprint := calculateFingerprint(certBlock.Bytes)
	log.Printf("[CA] Loaded root CA certificate from %s (fingerprint: %s)\n", certPath, fingerprint)

	return ca, nil
}

// calculateFingerprint computes the SHA-256 fingerprint of a certificate
func calculateFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return fmt.Sprintf("%x", hash)
}

// validateKeyStrength ensures private key meets minimum strength requirements
// Per constitution SR-001: 2048-bit RSA minimum or P-256 ECDSA
func validateKeyStrength(privateKey interface{}) error {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key size %d bits is below minimum 2048 bits", key.N.BitLen())
		}
		return nil
	case *ecdsa.PrivateKey:
		// P-256 curve has 256-bit keys
		if key.Curve != elliptic.P256() {
			return fmt.Errorf("ECDSA curve must be P-256, got %s", key.Curve.Params().Name)
		}
		return nil
	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}
}
