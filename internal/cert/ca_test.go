package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerate_CertificateFields(t *testing.T) {
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	cert := ca.Certificate()
	if cert == nil {
		t.Fatal("Certificate() returned nil after Generate")
	}

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "subject common name",
			check: func(t *testing.T) {
				t.Helper()
				if cert.Subject.CommonName != "yorishiro-proxy CA" {
					t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "yorishiro-proxy CA")
				}
			},
		},
		{
			name: "issuer equals subject (self-signed)",
			check: func(t *testing.T) {
				t.Helper()
				if cert.Issuer.CommonName != cert.Subject.CommonName {
					t.Errorf("Issuer.CommonName = %q, want %q (self-signed)", cert.Issuer.CommonName, cert.Subject.CommonName)
				}
			},
		},
		{
			name: "IsCA is true",
			check: func(t *testing.T) {
				t.Helper()
				if !cert.IsCA {
					t.Error("IsCA = false, want true")
				}
			},
		},
		{
			name: "BasicConstraintsValid is true",
			check: func(t *testing.T) {
				t.Helper()
				if !cert.BasicConstraintsValid {
					t.Error("BasicConstraintsValid = false, want true")
				}
			},
		},
		{
			name: "MaxPathLen is 0",
			check: func(t *testing.T) {
				t.Helper()
				if cert.MaxPathLen != 0 {
					t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
				}
			},
		},
		{
			name: "MaxPathLenZero is true",
			check: func(t *testing.T) {
				t.Helper()
				if !cert.MaxPathLenZero {
					t.Error("MaxPathLenZero = false, want true")
				}
			},
		},
		{
			name: "KeyUsage includes CertSign",
			check: func(t *testing.T) {
				t.Helper()
				if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
					t.Error("KeyUsage does not include CertSign")
				}
			},
		},
		{
			name: "KeyUsage includes CRLSign",
			check: func(t *testing.T) {
				t.Helper()
				if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
					t.Error("KeyUsage does not include CRLSign")
				}
			},
		},
		{
			name: "public key is ECDSA P-256",
			check: func(t *testing.T) {
				t.Helper()
				pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("PublicKey type = %T, want *ecdsa.PublicKey", cert.PublicKey)
				}
				if pub.Curve != elliptic.P256() {
					t.Errorf("PublicKey curve = %v, want P-256", pub.Curve.Params().Name)
				}
			},
		},
		{
			name: "validity period is approximately 10 years",
			check: func(t *testing.T) {
				t.Helper()
				duration := cert.NotAfter.Sub(cert.NotBefore)
				expected := caValidity
				// Allow 1-minute tolerance for test execution time.
				tolerance := time.Minute
				if duration < expected-tolerance || duration > expected+tolerance {
					t.Errorf("validity duration = %v, want ~%v", duration, expected)
				}
			},
		},
		{
			name: "NotBefore is not in the future",
			check: func(t *testing.T) {
				t.Helper()
				if cert.NotBefore.After(time.Now().Add(time.Minute)) {
					t.Errorf("NotBefore = %v, should not be in the future", cert.NotBefore)
				}
			},
		},
		{
			name: "serial number is positive",
			check: func(t *testing.T) {
				t.Helper()
				if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
					t.Errorf("SerialNumber = %v, want positive", cert.SerialNumber)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t)
		})
	}
}

func TestGenerate_CertPEM(t *testing.T) {
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	pemBytes := ca.CertPEM()
	if pemBytes == nil {
		t.Fatal("CertPEM() returned nil after Generate")
	}

	block, rest := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("CertPEM() returned data that cannot be PEM-decoded")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type = %q, want %q", block.Type, "CERTIFICATE")
	}
	if len(rest) != 0 {
		t.Errorf("PEM data has %d trailing bytes, want 0", len(rest))
	}

	// Verify the PEM can be parsed back to a certificate.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse PEM certificate: %v", err)
	}
	if cert.Subject.CommonName != "yorishiro-proxy CA" {
		t.Errorf("parsed cert CN = %q, want %q", cert.Subject.CommonName, "yorishiro-proxy CA")
	}
}

func TestGenerate_UniqueSerialNumbers(t *testing.T) {
	serials := make(map[string]struct{})

	for i := 0; i < 10; i++ {
		ca := &CA{}
		if err := ca.Generate(); err != nil {
			t.Fatalf("Generate #%d: %v", i, err)
		}

		serial := ca.Certificate().SerialNumber.String()
		if _, exists := serials[serial]; exists {
			t.Fatalf("duplicate serial number on iteration %d: %s", i, serial)
		}
		serials[serial] = struct{}{}
	}
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate and save.
	original := &CA{}
	if err := original.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := original.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load into a new CA.
	loaded := &CA{}
	if err := loaded.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify loaded certificate matches original.
	origCert := original.Certificate()
	loadedCert := loaded.Certificate()

	if origCert.Subject.CommonName != loadedCert.Subject.CommonName {
		t.Errorf("CN mismatch: original %q, loaded %q", origCert.Subject.CommonName, loadedCert.Subject.CommonName)
	}
	if origCert.SerialNumber.Cmp(loadedCert.SerialNumber) != 0 {
		t.Errorf("serial mismatch: original %s, loaded %s", origCert.SerialNumber, loadedCert.SerialNumber)
	}
	if !origCert.NotBefore.Equal(loadedCert.NotBefore) {
		t.Errorf("NotBefore mismatch: original %v, loaded %v", origCert.NotBefore, loadedCert.NotBefore)
	}
	if !origCert.NotAfter.Equal(loadedCert.NotAfter) {
		t.Errorf("NotAfter mismatch: original %v, loaded %v", origCert.NotAfter, loadedCert.NotAfter)
	}
	if loadedCert.IsCA != true {
		t.Error("loaded cert IsCA = false, want true")
	}

	// Verify loaded CertPEM is valid.
	loadedPEM := loaded.CertPEM()
	if loadedPEM == nil {
		t.Fatal("loaded CertPEM() returned nil")
	}
	block, _ := pem.Decode(loadedPEM)
	if block == nil {
		t.Fatal("loaded CertPEM() cannot be PEM-decoded")
	}
}

func TestSave_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ca.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	// Check cert file permissions (0644).
	if perm := certInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("cert file permissions = %o, want 0644", perm)
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	// Check key file permissions (0600).
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("key file permissions = %o, want 0600", perm)
	}
}

func TestSave_WithoutGenerateOrLoad(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca := &CA{}
	err := ca.Save(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error when saving without Generate or Load, got nil")
	}
}

func TestSave_InvalidCertPath(t *testing.T) {
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	err := ca.Save("/nonexistent-dir/cert.pem", filepath.Join(t.TempDir(), "key.pem"))
	if err == nil {
		t.Fatal("expected error for invalid cert path, got nil")
	}
}

func TestSave_InvalidKeyPath(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")

	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	err := ca.Save(certPath, "/nonexistent-dir/key.pem")
	if err == nil {
		t.Fatal("expected error for invalid key path, got nil")
	}
}

func TestLoad_NonexistentCertFile(t *testing.T) {
	dir := t.TempDir()
	ca := &CA{}
	err := ca.Load(filepath.Join(dir, "nonexistent.crt"), filepath.Join(dir, "nonexistent.key"))
	if err == nil {
		t.Fatal("expected error for nonexistent cert file, got nil")
	}
}

func TestLoad_NonexistentKeyFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")

	// Create a valid cert file but no key file.
	original := &CA{}
	if err := original.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := os.WriteFile(certPath, original.CertPEM(), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	ca := &CA{}
	err := ca.Load(certPath, filepath.Join(dir, "nonexistent.key"))
	if err == nil {
		t.Fatal("expected error for nonexistent key file, got nil")
	}
}

func TestLoad_InvalidPEM(t *testing.T) {
	tests := []struct {
		name     string
		certData []byte
		keyData  []byte
	}{
		{
			name:     "cert file is not PEM",
			certData: []byte("this is not PEM data"),
			keyData:  []byte("irrelevant"),
		},
		{
			name: "cert file has wrong PEM block type",
			certData: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: []byte("fake"),
			}),
			keyData: []byte("irrelevant"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "ca.crt")
			keyPath := filepath.Join(dir, "ca.key")

			if err := os.WriteFile(certPath, tt.certData, 0644); err != nil {
				t.Fatalf("write cert: %v", err)
			}
			if err := os.WriteFile(keyPath, tt.keyData, 0600); err != nil {
				t.Fatalf("write key: %v", err)
			}

			ca := &CA{}
			err := ca.Load(certPath, keyPath)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestLoad_InvalidKeyPEM(t *testing.T) {
	// Generate a valid cert, then provide invalid key PEM data.
	original := &CA{}
	if err := original.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tests := []struct {
		name    string
		keyData []byte
	}{
		{
			name:    "key file is not PEM",
			keyData: []byte("this is not PEM data"),
		},
		{
			name: "key file has wrong PEM block type",
			keyData: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte("fake"),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath := filepath.Join(dir, "ca.crt")
			keyPath := filepath.Join(dir, "ca.key")

			if err := os.WriteFile(certPath, original.CertPEM(), 0644); err != nil {
				t.Fatalf("write cert: %v", err)
			}
			if err := os.WriteFile(keyPath, tt.keyData, 0600); err != nil {
				t.Fatalf("write key: %v", err)
			}

			ca := &CA{}
			err := ca.Load(certPath, keyPath)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestLoad_MismatchedKeyAndCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate first CA and save its cert.
	ca1 := &CA{}
	if err := ca1.Generate(); err != nil {
		t.Fatalf("Generate ca1: %v", err)
	}
	if err := os.WriteFile(certPath, ca1.CertPEM(), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Generate second CA and save its key.
	ca2 := &CA{}
	if err := ca2.Generate(); err != nil {
		t.Fatalf("Generate ca2: %v", err)
	}
	// Save ca2's key.
	keyDER, err := x509.MarshalECPrivateKey(ca2.privKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// Load should fail because cert and key don't match.
	ca := &CA{}
	err = ca.Load(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key, got nil")
	}
}

func TestLoad_InvalidCertDER(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Write cert PEM with invalid DER content.
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER content"),
	})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Write a valid-looking key PEM with invalid DER.
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("invalid DER content"),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	ca := &CA{}
	err := ca.Load(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid cert DER, got nil")
	}
}

func TestLoad_InvalidKeyDER(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate a valid CA to get a real cert.
	original := &CA{}
	if err := original.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := os.WriteFile(certPath, original.CertPEM(), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Write key PEM with correct type but invalid DER content.
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("invalid DER content"),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	ca := &CA{}
	err := ca.Load(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid key DER, got nil")
	}
}

func TestCertificate_NilBeforeGenerate(t *testing.T) {
	ca := &CA{}
	if cert := ca.Certificate(); cert != nil {
		t.Errorf("Certificate() = %v, want nil before Generate", cert)
	}
}

func TestCertPEM_NilBeforeGenerate(t *testing.T) {
	ca := &CA{}
	if p := ca.CertPEM(); p != nil {
		t.Errorf("CertPEM() = %v, want nil before Generate", p)
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	sn, err := generateSerialNumber()
	if err != nil {
		t.Fatalf("generateSerialNumber: %v", err)
	}
	if sn == nil {
		t.Fatal("serial number is nil")
	}
	if sn.Sign() <= 0 {
		t.Errorf("serial number = %v, want positive", sn)
	}

	// Serial number should be less than 2^128.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	if sn.Cmp(limit) >= 0 {
		t.Errorf("serial number %v >= 2^128", sn)
	}
}

func TestGenerate_SelfSignedVerification(t *testing.T) {
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	cert := ca.Certificate()

	// Verify the certificate is self-signed by checking it against its own public key.
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	opts := x509.VerifyOptions{
		Roots: pool,
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("self-signed verification failed: %v", err)
	}
}

func TestSave_OverwritesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Write dummy data first.
	if err := os.WriteFile(certPath, []byte("old cert"), 0644); err != nil {
		t.Fatalf("write old cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old key"), 0600); err != nil {
		t.Fatalf("write old key: %v", err)
	}

	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ca.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify the files were overwritten with valid PEM data.
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("saved cert file is not valid PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("saved cert PEM type = %q, want CERTIFICATE", block.Type)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		t.Fatal("saved key file is not valid PEM")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("saved key PEM type = %q, want EC PRIVATE KEY", keyBlock.Type)
	}
}

func TestGenerate_MultipleCalls(t *testing.T) {
	ca := &CA{}

	// First generation.
	if err := ca.Generate(); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	firstSerial := ca.Certificate().SerialNumber

	// Second generation should overwrite.
	if err := ca.Generate(); err != nil {
		t.Fatalf("second Generate: %v", err)
	}
	secondSerial := ca.Certificate().SerialNumber

	// Serials should differ (extremely high probability).
	if firstSerial.Cmp(secondSerial) == 0 {
		t.Error("two successive Generate calls produced the same serial number")
	}
}

func TestLoad_EmptyFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Create empty files.
	if err := os.WriteFile(certPath, []byte{}, 0644); err != nil {
		t.Fatalf("write empty cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte{}, 0600); err != nil {
		t.Fatalf("write empty key: %v", err)
	}

	ca := &CA{}
	err := ca.Load(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for empty files, got nil")
	}
}

func TestGenerate_KeyCurveIsP256(t *testing.T) {
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Access private key directly to verify curve.
	if ca.privKey == nil {
		t.Fatal("privKey is nil after Generate")
	}
	if ca.privKey.Curve != elliptic.P256() {
		t.Errorf("private key curve = %v, want P-256", ca.privKey.Curve.Params().Name)
	}
}

func TestCASource_DefaultZeroValue(t *testing.T) {
	ca := &CA{}
	source := ca.Source()
	if source.Persisted {
		t.Error("new CA should have Persisted=false")
	}
	if source.CertPath != "" {
		t.Errorf("new CA CertPath = %q, want empty", source.CertPath)
	}
	if source.KeyPath != "" {
		t.Errorf("new CA KeyPath = %q, want empty", source.KeyPath)
	}
}

func TestCASource_SetAndGet(t *testing.T) {
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	expected := CASource{
		Persisted: true,
		CertPath:  "/tmp/ca.crt",
		KeyPath:   "/tmp/ca.key",
	}
	ca.SetSource(expected)

	got := ca.Source()
	if got != expected {
		t.Errorf("Source() = %+v, want %+v", got, expected)
	}
}

func TestCASource_PreservedAfterGenerate(t *testing.T) {
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("first Generate: %v", err)
	}

	ca.SetSource(CASource{Persisted: true, CertPath: "/test/ca.crt"})

	// Generate again — source should be reset to zero value since Generate doesn't preserve source.
	if err := ca.Generate(); err != nil {
		t.Fatalf("second Generate: %v", err)
	}

	// Source is NOT automatically reset by Generate; it's the caller's responsibility.
	// This tests that SetSource is independent of Generate.
	source := ca.Source()
	if !source.Persisted {
		t.Error("Source was unexpectedly reset after Generate")
	}
}

func TestSaveAndLoad_PreservesSigningCapability(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Generate, save, and load.
	original := &CA{}
	if err := original.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := original.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded := &CA{}
	if err := loaded.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Use the loaded CA to sign some data, verifying the key is functional.
	data := []byte("test data to sign")
	r, s, err := ecdsa.Sign(rand.Reader, loaded.privKey, data)
	if err != nil {
		t.Fatalf("sign with loaded key: %v", err)
	}

	// Verify signature using the public key from the loaded certificate.
	pub := loaded.Certificate().PublicKey.(*ecdsa.PublicKey)
	if !ecdsa.Verify(pub, data, r, s) {
		t.Error("signature verification failed with loaded CA key")
	}
}
