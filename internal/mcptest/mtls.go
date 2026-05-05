package mcptest

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
	"path/filepath"
	"time"
)

// MTLSMaterial collects the on-disk and in-memory artifacts needed to
// drive a mutual-TLS scenario through the proxy. The CA pool is wired
// into the upstream test server (so it accepts client certificates
// signed by CA), and the client cert / key paths are passed to
// proxy_start's client_cert / client_key fields.
//
// All material is generated fresh per harness instance — no shared
// state, no on-disk leakage outside t.TempDir().
type MTLSMaterial struct {
	// CACertPEM is the PEM-encoded test CA certificate. Use
	// x509.NewCertPool().AppendCertsFromPEM(CACertPEM) to construct
	// the upstream server's ClientCAs pool.
	CACertPEM []byte

	// ClientCertPath is the on-disk path to the client certificate
	// PEM, suitable for proxy_start's client_cert field. The file is
	// written under t.TempDir(), so it disappears when the test ends.
	ClientCertPath string

	// ClientKeyPath is the on-disk path to the client private key PEM,
	// suitable for proxy_start's client_key field.
	ClientKeyPath string
}

// generateMTLSMaterial creates a fresh test CA, signs a client
// certificate with it, and writes the client cert + key PEMs to the
// given directory. Returns the generated material (CA cert PEM in
// memory + client paths on disk).
//
// Implementation is intentionally minimal:
//   - ECDSA P-256 (matches internal/cert/ca.go style)
//   - 1-hour validity (tests don't need long-lived material)
//   - SAN includes "client.test" + 127.0.0.1 so the cert is usable for
//     either subject-name or IP verification, though
//     RequireAndVerifyClientCert only checks the chain.
//
// Errors are returned wrapped — callers (StartHarness) translate them
// to t.Fatalf.
func generateMTLSMaterial(dir string) (*MTLSMaterial, error) {
	// --- CA ---
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	caSerial, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName: "yorishiro-proxy mcptest mTLS CA",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(1 * time.Hour),
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// --- Client cert ---
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client key: %w", err)
	}
	clientSerial, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate client serial: %w", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			CommonName: "yorishiro-proxy mcptest mTLS client",
		},
		NotBefore:   now.Add(-1 * time.Minute),
		NotAfter:    now.Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create client certificate: %w", err)
	}
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})

	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, fmt.Errorf("marshal client private key: %w", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	// --- Write client material to disk ---
	clientCertPath := filepath.Join(dir, "client.crt")
	if err := os.WriteFile(clientCertPath, clientCertPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write client cert: %w", err)
	}
	clientKeyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(clientKeyPath, clientKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write client key: %w", err)
	}

	return &MTLSMaterial{
		CACertPEM:      caCertPEM,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
	}, nil
}
