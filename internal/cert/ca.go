package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// caValidity is the validity period for a generated CA certificate.
const caValidity = 10 * 365 * 24 * time.Hour // ~10 years

// CASource tracks the persistence state of a CA.
type CASource struct {
	Persisted bool
	CertPath  string
	KeyPath   string
	Explicit  bool // true when CA was loaded from user-provided -ca-cert/-ca-key flags
}

// CA manages the root certificate authority for TLS interception.
// All exported methods are safe for concurrent use.
type CA struct {
	mu      sync.RWMutex
	cert    *x509.Certificate
	privKey *ecdsa.PrivateKey
	certPEM []byte
	source  CASource
}

// Generate creates a new self-signed root CA certificate and ECDSA P-256 private key.
// The generated CA has Subject CN=katashiro-proxy CA, 10-year validity,
// BasicConstraints IsCA=true with MaxPathLen=0, and KeyUsage CertSign|CRLSign.
func (ca *CA) Generate() error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ECDSA key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "katashiro-proxy CA",
		},
		NotBefore:             now,
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse generated CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	ca.mu.Lock()
	ca.cert = cert
	ca.privKey = privKey
	ca.certPEM = certPEM
	ca.mu.Unlock()

	return nil
}

// Load reads an existing CA certificate and private key from PEM-encoded files.
func (ca *CA) Load(certPath, keyPath string) error {
	certPEMData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read CA certificate file %s: %w", certPath, err)
	}

	keyPEMData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read CA key file %s: %w", keyPath, err)
	}

	// Decode certificate PEM.
	certBlock, _ := pem.Decode(certPEMData)
	if certBlock == nil {
		return fmt.Errorf("decode CA certificate PEM: no PEM block found in %s", certPath)
	}
	if certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("decode CA certificate PEM: unexpected block type %q, want CERTIFICATE", certBlock.Type)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	// Decode private key PEM.
	keyBlock, _ := pem.Decode(keyPEMData)
	if keyBlock == nil {
		return fmt.Errorf("decode CA key PEM: no PEM block found in %s", keyPath)
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		return fmt.Errorf("decode CA key PEM: unexpected block type %q, want EC PRIVATE KEY", keyBlock.Type)
	}

	privKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA private key: %w", err)
	}

	// Verify the key matches the certificate.
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&privKey.PublicKey) {
		return fmt.Errorf("CA certificate and private key do not match")
	}

	ca.mu.Lock()
	ca.cert = cert
	ca.privKey = privKey
	ca.certPEM = certPEMData
	ca.mu.Unlock()

	return nil
}

// Save writes the CA certificate and private key to PEM-encoded files.
// Files are created with restrictive permissions: 0644 for the certificate
// and 0600 for the private key.
func (ca *CA) Save(certPath, keyPath string) error {
	ca.mu.RLock()
	cert := ca.cert
	privKey := ca.privKey
	certPEM := ca.certPEM
	ca.mu.RUnlock()

	if cert == nil || privKey == nil {
		return fmt.Errorf("save CA: no certificate or key to save (call Generate or Load first)")
	}

	// Encode private key to PEM.
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal CA private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	// Write certificate file (world-readable).
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write CA certificate file %s: %w", certPath, err)
	}

	// Write private key file (owner-only).
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write CA key file %s: %w", keyPath, err)
	}

	return nil
}

// Certificate returns the CA's parsed x509 certificate, or nil if not loaded/generated.
func (ca *CA) Certificate() *x509.Certificate {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.cert
}

// PrivateKey returns the CA's ECDSA private key, or nil if not loaded/generated.
func (ca *CA) PrivateKey() *ecdsa.PrivateKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.privKey
}

// CertPEM returns the PEM-encoded CA certificate bytes, or nil if not loaded/generated.
func (ca *CA) CertPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.certPEM
}

// SigningPair returns a consistent snapshot of the CA certificate and private key.
// This is used by Issuer to avoid reading cert and privKey at different times.
func (ca *CA) SigningPair() (*x509.Certificate, *ecdsa.PrivateKey) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.cert, ca.privKey
}

// Source returns the persistence metadata for this CA.
func (ca *CA) Source() CASource {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.source
}

// SetSource sets the persistence metadata for this CA.
func (ca *CA) SetSource(s CASource) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.source = s
}

// generateSerialNumber creates a random 128-bit serial number for certificates.
func generateSerialNumber() (*big.Int, error) {
	// Use 128 bits per RFC 5280 recommendation.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate random serial: %w", err)
	}
	return serialNumber, nil
}
