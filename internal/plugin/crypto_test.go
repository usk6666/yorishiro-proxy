package plugin

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// execStarlark is a test helper that executes a Starlark script with the crypto module.
func execStarlark(t *testing.T, script string) starlark.StringDict {
	t.Helper()
	thread := &starlark.Thread{Name: "test"}
	predeclared := starlark.StringDict{
		"action": newActionModule(),
		"crypto": newCryptoModule(),
	}
	globals, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread,
		"test.star",
		[]byte(script),
		predeclared,
	)
	if err != nil {
		t.Fatalf("exec script: %v", err)
	}
	return globals
}

// execStarlarkErr is a test helper that expects a Starlark script to fail.
func execStarlarkErr(t *testing.T, script string) error {
	t.Helper()
	thread := &starlark.Thread{Name: "test"}
	predeclared := starlark.StringDict{
		"action": newActionModule(),
		"crypto": newCryptoModule(),
	}
	_, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread,
		"test.star",
		[]byte(script),
		predeclared,
	)
	return err
}

func TestCrypto_Hash(t *testing.T) {
	tests := []struct {
		name     string
		funcName string
		input    string
		wantHex  string
	}{
		{
			name:     "md5 empty",
			funcName: "md5",
			input:    "",
			wantHex:  "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:     "md5 hello",
			funcName: "md5",
			input:    "hello",
			wantHex:  "5d41402abc4b2a76b9719d911017c592",
		},
		{
			name:     "sha1 empty",
			funcName: "sha1",
			input:    "",
			wantHex:  "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			name:     "sha1 hello",
			funcName: "sha1",
			input:    "hello",
			wantHex:  "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
		},
		{
			name:     "sha256 empty",
			funcName: "sha256",
			input:    "",
			wantHex:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "sha256 hello",
			funcName: "sha256",
			input:    "hello",
			wantHex:  "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "sha512 empty",
			funcName: "sha512",
			input:    "",
			wantHex:  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
		{
			name:     "sha512 hello",
			funcName: "sha512",
			input:    "hello",
			wantHex:  "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := `result = crypto.` + tt.funcName + `(b"` + tt.input + `")`
			globals := execStarlark(t, script)
			got := globals["result"]
			gotBytes, ok := got.(starlark.Bytes)
			if !ok {
				t.Fatalf("result type = %T, want starlark.Bytes", got)
			}
			gotHex := hex.EncodeToString([]byte(gotBytes))
			if gotHex != tt.wantHex {
				t.Errorf("got %s, want %s", gotHex, tt.wantHex)
			}
		})
	}
}

func TestCrypto_Hash_TypeError(t *testing.T) {
	// Passing a string instead of bytes should fail.
	err := execStarlarkErr(t, `result = crypto.sha256("hello")`)
	if err == nil {
		t.Fatal("expected error for string argument, got nil")
	}
}

func TestCrypto_Hash_WrongArgCount(t *testing.T) {
	err := execStarlarkErr(t, `result = crypto.sha256(b"a", b"b")`)
	if err == nil {
		t.Fatal("expected error for wrong arg count, got nil")
	}
}

// TestCrypto_HMAC tests HMAC functions against RFC 4231 test vectors.
func TestCrypto_HMAC(t *testing.T) {
	tests := []struct {
		name     string
		funcName string
		keyHex   string
		msgHex   string
		wantHex  string
	}{
		// RFC 4231 Test Case 2 - "Jefe" / "what do ya want for nothing?"
		{
			name:     "hmac_sha256 RFC4231 TC2",
			funcName: "hmac_sha256",
			keyHex:   "4a656665",                                                         // "Jefe"
			msgHex:   "7768617420646f2079612077616e7420666f72206e6f7468696e673f",         // "what do ya want for nothing?"
			wantHex:  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", // RFC 4231
		},
		{
			name:     "hmac_sha512 RFC4231 TC2",
			funcName: "hmac_sha512",
			keyHex:   "4a656665",
			msgHex:   "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			wantHex:  "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		},
		// RFC 2104 / common test vector for HMAC-MD5
		{
			name:     "hmac_md5 RFC2104",
			funcName: "hmac_md5",
			keyHex:   "4a656665",
			msgHex:   "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			wantHex:  "750c783e6ab0b503eaa86e310a5db738",
		},
		// HMAC-SHA1 test vector
		{
			name:     "hmac_sha1 RFC2202 TC2",
			funcName: "hmac_sha1",
			keyHex:   "4a656665",
			msgHex:   "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			wantHex:  "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build script that uses hex_decode to construct bytes.
			script := `
key = crypto.hex_decode("` + tt.keyHex + `")
msg = crypto.hex_decode("` + tt.msgHex + `")
result = crypto.` + tt.funcName + `(key, msg)
result_hex = crypto.hex_encode(result)
`
			globals := execStarlark(t, script)
			got, ok := globals["result_hex"].(starlark.String)
			if !ok {
				t.Fatalf("result_hex type = %T, want starlark.String", globals["result_hex"])
			}
			if string(got) != tt.wantHex {
				t.Errorf("got %s, want %s", got, tt.wantHex)
			}
		})
	}
}

func TestCrypto_HMAC_TypeError(t *testing.T) {
	err := execStarlarkErr(t, `result = crypto.hmac_sha256("key", b"msg")`)
	if err == nil {
		t.Fatal("expected error for string key, got nil")
	}
}

func TestCrypto_AES_CBC_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		message string
	}{
		{"AES-128", 16, "Hello, World!"},
		{"AES-192", 24, "Hello, World!"},
		{"AES-256", 32, "Hello, World!"},
		{"empty plaintext", 16, ""},
		{"exact block size", 16, "1234567890123456"},
		{"multi block", 16, "This message spans multiple AES blocks for testing purposes."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyHex := hex.EncodeToString(bytes.Repeat([]byte{0xAB}, tt.keyLen))
			ivHex := hex.EncodeToString(bytes.Repeat([]byte{0xCD}, 16))
			msgHex := hex.EncodeToString([]byte(tt.message))

			script := `
key = crypto.hex_decode("` + keyHex + `")
iv = crypto.hex_decode("` + ivHex + `")
msg = crypto.hex_decode("` + msgHex + `")
encrypted = crypto.aes_encrypt_cbc(key, iv, msg)
decrypted = crypto.aes_decrypt_cbc(key, iv, encrypted)
`
			globals := execStarlark(t, script)
			decrypted, ok := globals["decrypted"].(starlark.Bytes)
			if !ok {
				t.Fatalf("decrypted type = %T, want starlark.Bytes", globals["decrypted"])
			}
			if string(decrypted) != tt.message {
				t.Errorf("got %q, want %q", string(decrypted), tt.message)
			}
		})
	}
}

func TestCrypto_AES_CBC_InvalidKeyLength(t *testing.T) {
	err := execStarlarkErr(t, `
key = b"shortkey"
iv = crypto.hex_decode("00000000000000000000000000000000")
crypto.aes_encrypt_cbc(key, iv, b"test")
`)
	if err == nil {
		t.Fatal("expected error for invalid key length, got nil")
	}
}

func TestCrypto_AES_CBC_InvalidIVLength(t *testing.T) {
	err := execStarlarkErr(t, `
key = crypto.hex_decode("00000000000000000000000000000000")
iv = b"short"
crypto.aes_encrypt_cbc(key, iv, b"test")
`)
	if err == nil {
		t.Fatal("expected error for invalid IV length, got nil")
	}
}

func TestCrypto_AES_CBC_InvalidCiphertext(t *testing.T) {
	// Ciphertext not a multiple of block size.
	err := execStarlarkErr(t, `
key = crypto.hex_decode("00000000000000000000000000000000")
iv = crypto.hex_decode("00000000000000000000000000000000")
crypto.aes_decrypt_cbc(key, iv, b"short")
`)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext length, got nil")
	}
}

func TestCrypto_AES_CBC_EmptyCiphertext(t *testing.T) {
	err := execStarlarkErr(t, `
key = crypto.hex_decode("00000000000000000000000000000000")
iv = crypto.hex_decode("00000000000000000000000000000000")
crypto.aes_decrypt_cbc(key, iv, b"")
`)
	if err == nil {
		t.Fatal("expected error for empty ciphertext, got nil")
	}
}

func TestCrypto_AES_GCM_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		message string
		aad     string
	}{
		{"AES-128 no AAD", 16, "Hello, World!", ""},
		{"AES-256 with AAD", 32, "Secret message", "additional data"},
		{"empty plaintext", 16, "", ""},
		{"empty plaintext with AAD", 16, "", "some context"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyHex := hex.EncodeToString(bytes.Repeat([]byte{0xAB}, tt.keyLen))
			nonceHex := hex.EncodeToString(bytes.Repeat([]byte{0xCD}, 12)) // GCM nonce is 12 bytes
			msgHex := hex.EncodeToString([]byte(tt.message))
			aadHex := hex.EncodeToString([]byte(tt.aad))

			script := `
key = crypto.hex_decode("` + keyHex + `")
nonce = crypto.hex_decode("` + nonceHex + `")
msg = crypto.hex_decode("` + msgHex + `")
aad = crypto.hex_decode("` + aadHex + `")
encrypted = crypto.aes_encrypt_gcm(key, nonce, msg, aad)
decrypted = crypto.aes_decrypt_gcm(key, nonce, encrypted, aad)
`
			globals := execStarlark(t, script)
			decrypted, ok := globals["decrypted"].(starlark.Bytes)
			if !ok {
				t.Fatalf("decrypted type = %T, want starlark.Bytes", globals["decrypted"])
			}
			if string(decrypted) != tt.message {
				t.Errorf("got %q, want %q", string(decrypted), tt.message)
			}
		})
	}
}

func TestCrypto_AES_GCM_InvalidKeyLength(t *testing.T) {
	err := execStarlarkErr(t, `
key = b"shortkey"
nonce = crypto.hex_decode("000000000000000000000000")
crypto.aes_encrypt_gcm(key, nonce, b"test", b"")
`)
	if err == nil {
		t.Fatal("expected error for invalid key length, got nil")
	}
}

func TestCrypto_AES_GCM_InvalidNonceLength(t *testing.T) {
	err := execStarlarkErr(t, `
key = crypto.hex_decode("00000000000000000000000000000000")
nonce = b"short"
crypto.aes_encrypt_gcm(key, nonce, b"test", b"")
`)
	if err == nil {
		t.Fatal("expected error for invalid nonce length, got nil")
	}
}

func TestCrypto_AES_GCM_TamperedCiphertext(t *testing.T) {
	err := execStarlarkErr(t, `
key = crypto.hex_decode("00000000000000000000000000000000")
nonce = crypto.hex_decode("000000000000000000000000")
encrypted = crypto.aes_encrypt_gcm(key, nonce, b"hello", b"")
# Tamper with the ciphertext by flipping bits.
tampered = crypto.hex_decode("ff" * len(crypto.hex_encode(encrypted)) + "00")
crypto.aes_decrypt_gcm(key, nonce, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", b"")
`)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext, got nil")
	}
}

func TestCrypto_AES_GCM_WrongAAD(t *testing.T) {
	err := execStarlarkErr(t, `
key = crypto.hex_decode("00000000000000000000000000000000")
nonce = crypto.hex_decode("000000000000000000000000")
encrypted = crypto.aes_encrypt_gcm(key, nonce, b"hello", b"correct aad")
crypto.aes_decrypt_gcm(key, nonce, encrypted, b"wrong aad")
`)
	if err == nil {
		t.Fatal("expected error for wrong AAD, got nil")
	}
}

func TestCrypto_HexRoundTrip(t *testing.T) {
	script := `
original = b"\x00\x01\x02\xff\xfe\xfd"
encoded = crypto.hex_encode(original)
decoded = crypto.hex_decode(encoded)
`
	globals := execStarlark(t, script)
	encoded, ok := globals["encoded"].(starlark.String)
	if !ok {
		t.Fatalf("encoded type = %T, want starlark.String", globals["encoded"])
	}
	if string(encoded) != "000102fffefd" {
		t.Errorf("encoded = %q, want %q", encoded, "000102fffefd")
	}
	decoded, ok := globals["decoded"].(starlark.Bytes)
	if !ok {
		t.Fatalf("decoded type = %T, want starlark.Bytes", globals["decoded"])
	}
	want := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}
	if !bytes.Equal([]byte(decoded), want) {
		t.Errorf("decoded = %v, want %v", []byte(decoded), want)
	}
}

func TestCrypto_HexDecode_Invalid(t *testing.T) {
	err := execStarlarkErr(t, `crypto.hex_decode("xyz")`)
	if err == nil {
		t.Fatal("expected error for invalid hex, got nil")
	}
}

func TestCrypto_HexEncode_TypeError(t *testing.T) {
	err := execStarlarkErr(t, `crypto.hex_encode("not bytes")`)
	if err == nil {
		t.Fatal("expected error for string argument, got nil")
	}
}

func TestCrypto_HexDecode_TypeError(t *testing.T) {
	err := execStarlarkErr(t, `crypto.hex_decode(b"not string")`)
	if err == nil {
		t.Fatal("expected error for bytes argument, got nil")
	}
}

func TestCrypto_Base64RoundTrip(t *testing.T) {
	script := `
original = b"Hello, World!"
encoded = crypto.base64_encode(original)
decoded = crypto.base64_decode(encoded)
`
	globals := execStarlark(t, script)
	encoded, ok := globals["encoded"].(starlark.String)
	if !ok {
		t.Fatalf("encoded type = %T, want starlark.String", globals["encoded"])
	}
	if string(encoded) != "SGVsbG8sIFdvcmxkIQ==" {
		t.Errorf("encoded = %q, want %q", encoded, "SGVsbG8sIFdvcmxkIQ==")
	}
	decoded, ok := globals["decoded"].(starlark.Bytes)
	if !ok {
		t.Fatalf("decoded type = %T, want starlark.Bytes", globals["decoded"])
	}
	if string(decoded) != "Hello, World!" {
		t.Errorf("decoded = %q, want %q", string(decoded), "Hello, World!")
	}
}

func TestCrypto_Base64Decode_Invalid(t *testing.T) {
	err := execStarlarkErr(t, `crypto.base64_decode("!!!invalid!!!")`)
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestCrypto_Base64URLRoundTrip(t *testing.T) {
	// Data that produces +/ in standard base64.
	script := `
original = b"\xfb\xff\xfe"
encoded = crypto.base64url_encode(original)
decoded = crypto.base64url_decode(encoded)
`
	globals := execStarlark(t, script)
	encoded, ok := globals["encoded"].(starlark.String)
	if !ok {
		t.Fatalf("encoded type = %T, want starlark.String", globals["encoded"])
	}
	// Ensure no padding and URL-safe characters.
	for _, c := range string(encoded) {
		if c == '+' || c == '/' || c == '=' {
			t.Errorf("encoded contains non-URL-safe character: %q", string(c))
		}
	}
	decoded, ok := globals["decoded"].(starlark.Bytes)
	if !ok {
		t.Fatalf("decoded type = %T, want starlark.Bytes", globals["decoded"])
	}
	want := []byte{0xfb, 0xff, 0xfe}
	if !bytes.Equal([]byte(decoded), want) {
		t.Errorf("decoded = %v, want %v", []byte(decoded), want)
	}
}

func TestCrypto_Base64URLDecode_Invalid(t *testing.T) {
	err := execStarlarkErr(t, `crypto.base64url_decode("!!!invalid!!!")`)
	if err == nil {
		t.Fatal("expected error for invalid base64url, got nil")
	}
}

func TestCrypto_PKCS7(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		wantLen   int
	}{
		{"empty", []byte{}, 16, 16},
		{"partial block", []byte("hello"), 16, 16},
		{"exact block", bytes.Repeat([]byte{0x41}, 16), 16, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.input, tt.blockSize)
			if len(padded) != tt.wantLen {
				t.Errorf("padded length = %d, want %d", len(padded), tt.wantLen)
			}
			if len(padded)%tt.blockSize != 0 {
				t.Errorf("padded length %d not a multiple of block size %d", len(padded), tt.blockSize)
			}
			unpadded, err := pkcs7Unpad(padded, tt.blockSize)
			if err != nil {
				t.Fatalf("unpad error: %v", err)
			}
			if !bytes.Equal(unpadded, tt.input) {
				t.Errorf("unpadded = %v, want %v", unpadded, tt.input)
			}
		})
	}
}

func TestCrypto_PKCS7Unpad_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		block int
	}{
		{"empty", []byte{}, 16},
		{"wrong length", []byte{1, 2, 3}, 16},
		{"zero padding", bytes.Repeat([]byte{0}, 16), 16},
		{"padding too large", append(bytes.Repeat([]byte{0x41}, 15), 17), 16},
		{"inconsistent padding", append(bytes.Repeat([]byte{0x41}, 14), 2, 3), 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tt.data, tt.block)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestCrypto_AWS4Signature tests a simplified AWS4 signature computation
// to validate the crypto module works for real-world use cases.
func TestCrypto_AWS4Signature(t *testing.T) {
	// This test follows the AWS Signature Version 4 signing process:
	// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
	// Pre-compute "AWS4" + secret_key as hex for the HMAC key.
	// Starlark bytes do not support the + operator.
	aws4Key := "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	aws4KeyHex := hex.EncodeToString([]byte(aws4Key))

	script := `
# Step 1: Create a signing key
# "AWS4" + secret_key pre-computed as hex since Starlark bytes don't support +.
aws4_key = crypto.hex_decode("` + aws4KeyHex + `")
date_stamp = b"20150830"
region = b"us-east-1"
service = b"iam"

k_date = crypto.hmac_sha256(aws4_key, date_stamp)
k_region = crypto.hmac_sha256(k_date, region)
k_service = crypto.hmac_sha256(k_region, service)
signing_key = crypto.hmac_sha256(k_service, b"aws4_request")
signing_key_hex = crypto.hex_encode(signing_key)

# Step 2: Sign a string_to_sign
string_to_sign = b"AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
signature = crypto.hmac_sha256(signing_key, string_to_sign)
signature_hex = crypto.hex_encode(signature)
`
	globals := execStarlark(t, script)

	// Verify the signing key matches the AWS documentation example.
	signingKeyHex, ok := globals["signing_key_hex"].(starlark.String)
	if !ok {
		t.Fatalf("signing_key_hex type = %T, want starlark.String", globals["signing_key_hex"])
	}
	wantSigningKey := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if string(signingKeyHex) != wantSigningKey {
		t.Errorf("signing_key = %s, want %s", signingKeyHex, wantSigningKey)
	}

	// Verify the signature matches the AWS documentation example.
	signatureHex, ok := globals["signature_hex"].(starlark.String)
	if !ok {
		t.Fatalf("signature_hex type = %T, want starlark.String", globals["signature_hex"])
	}
	wantSignature := "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if string(signatureHex) != wantSignature {
		t.Errorf("signature = %s, want %s", signatureHex, wantSignature)
	}
}

// TestCrypto_ModuleAvailableInPlugin verifies the crypto module is available
// when loading a plugin through the Engine.
func TestCrypto_ModuleAvailableInPlugin(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "crypto_test.star", `
def on_receive_from_client(data):
    # Use the crypto module to compute a hash.
    h = crypto.sha256(b"test")
    data["hash"] = crypto.hex_encode(h)
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
			OnError:  "skip",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	data := map[string]any{"method": "GET"}
	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil {
		t.Fatal("Dispatch() returned nil result")
	}

	wantHash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	gotHash, ok := result.Data["hash"]
	if !ok {
		t.Fatal("result.Data missing 'hash' key")
	}
	if gotHash != wantHash {
		t.Errorf("hash = %v, want %v", gotHash, wantHash)
	}
}

// TestCrypto_GoHashConsistency verifies Starlark crypto functions produce
// the same output as Go's crypto package directly.
func TestCrypto_GoHashConsistency(t *testing.T) {
	input := []byte("The quick brown fox jumps over the lazy dog")

	tests := []struct {
		name     string
		funcName string
		goHash   []byte
	}{
		{"md5", "md5", hashBytes(md5.New(), input)},
		{"sha1", "sha1", hashBytes(sha1.New(), input)},
		{"sha256", "sha256", hashBytes(sha256.New(), input)},
		{"sha512", "sha512", hashBytes(sha512.New(), input)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputHex := hex.EncodeToString(input)
			script := `
data = crypto.hex_decode("` + inputHex + `")
result = crypto.` + tt.funcName + `(data)
`
			globals := execStarlark(t, script)
			result, ok := globals["result"].(starlark.Bytes)
			if !ok {
				t.Fatalf("result type = %T, want starlark.Bytes", globals["result"])
			}
			if !bytes.Equal([]byte(result), tt.goHash) {
				t.Errorf("got %x, want %x", []byte(result), tt.goHash)
			}
		})
	}
}

func hashBytes(h interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}, data []byte) []byte {
	h.Write(data)
	return h.Sum(nil)
}

// TestCrypto_AES_CBC_KnownVector tests AES-CBC against a known test vector.
func TestCrypto_AES_CBC_KnownVector(t *testing.T) {
	// NIST SP 800-38A F.2.1 CBC-AES128.Encrypt
	keyHex := "2b7e151628aed2a6abf7158809cf4f3c"
	ivHex := "000102030405060708090a0b0c0d0e0f"
	ptHex := "6bc1bee22e409f96e93d7e117393172a"
	wantCtHex := "7649abac8119b246cee98e9b12e9197d"

	script := `
key = crypto.hex_decode("` + keyHex + `")
iv = crypto.hex_decode("` + ivHex + `")
pt = crypto.hex_decode("` + ptHex + `")
ct = crypto.aes_encrypt_cbc(key, iv, pt)
ct_hex = crypto.hex_encode(ct)
`
	globals := execStarlark(t, script)
	ctHex, ok := globals["ct_hex"].(starlark.String)
	if !ok {
		t.Fatalf("ct_hex type = %T, want starlark.String", globals["ct_hex"])
	}
	// The ciphertext includes PKCS#7 padding, so the first block should match.
	// With PKCS#7 padding the output is 2 blocks (32 bytes = 64 hex chars).
	got := string(ctHex)
	if len(got) != 64 {
		t.Fatalf("ciphertext hex length = %d, want 64", len(got))
	}
	// First block (32 hex chars) should match the NIST vector.
	if got[:32] != wantCtHex {
		t.Errorf("first block = %s, want %s", got[:32], wantCtHex)
	}
}

// TestCrypto_AES_GCM_KnownVector tests AES-GCM against NIST test vectors.
func TestCrypto_AES_GCM_KnownVector(t *testing.T) {
	// Test with AES-128-GCM encryption and then verify round-trip.
	keyHex := "00000000000000000000000000000000"
	nonceHex := "000000000000000000000000"
	ptHex := ""

	script := `
key = crypto.hex_decode("` + keyHex + `")
nonce = crypto.hex_decode("` + nonceHex + `")
pt = crypto.hex_decode("` + ptHex + `")
ct = crypto.aes_encrypt_gcm(key, nonce, pt, b"")
ct_hex = crypto.hex_encode(ct)
`
	globals := execStarlark(t, script)
	ctHex, ok := globals["ct_hex"].(starlark.String)
	if !ok {
		t.Fatalf("ct_hex type = %T, want starlark.String", globals["ct_hex"])
	}
	// For empty plaintext with zero key/nonce, the output is just the 16-byte tag.
	// Known value: 58e2fccefa7e3061367f1d57a4e7455a
	wantTag := "58e2fccefa7e3061367f1d57a4e7455a"
	if string(ctHex) != wantTag {
		t.Errorf("GCM tag = %s, want %s", ctHex, wantTag)
	}
}

// TestCrypto_AES_CBC_DecryptKeyLen tests key length validation for decrypt.
func TestCrypto_AES_CBC_DecryptKeyLen(t *testing.T) {
	keySizes := []int{1, 8, 15, 17, 31, 33, 64}
	for _, sz := range keySizes {
		keyHex := hex.EncodeToString(bytes.Repeat([]byte{0x00}, sz))
		err := execStarlarkErr(t, `
key = crypto.hex_decode("`+keyHex+`")
iv = crypto.hex_decode("00000000000000000000000000000000")
ct = crypto.hex_decode("00000000000000000000000000000000")
crypto.aes_decrypt_cbc(key, iv, ct)
`)
		if err == nil {
			t.Errorf("expected error for key size %d, got nil", sz)
		}
	}
}

// TestCrypto_AES_GCM_DecryptInvalidNonce tests nonce validation for GCM decrypt.
func TestCrypto_AES_GCM_DecryptInvalidNonce(t *testing.T) {
	err := execStarlarkErr(t, `
key = crypto.hex_decode("00000000000000000000000000000000")
nonce = b"short"
ct = crypto.hex_decode("00000000000000000000000000000000")
crypto.aes_decrypt_gcm(key, nonce, ct, b"")
`)
	if err == nil {
		t.Fatal("expected error for invalid nonce length, got nil")
	}
}

// TestCrypto_Base64_EmptyInput tests encoding/decoding of empty input.
func TestCrypto_Base64_EmptyInput(t *testing.T) {
	script := `
e1 = crypto.base64_encode(b"")
d1 = crypto.base64_decode("")
e2 = crypto.base64url_encode(b"")
d2 = crypto.base64url_decode("")
e3 = crypto.hex_encode(b"")
d3 = crypto.hex_decode("")
`
	globals := execStarlark(t, script)
	if s := globals["e1"].(starlark.String); string(s) != "" {
		t.Errorf("base64_encode empty = %q", s)
	}
	if b := globals["d1"].(starlark.Bytes); len(b) != 0 {
		t.Errorf("base64_decode empty = %v", []byte(b))
	}
	if s := globals["e2"].(starlark.String); string(s) != "" {
		t.Errorf("base64url_encode empty = %q", s)
	}
	if b := globals["d2"].(starlark.Bytes); len(b) != 0 {
		t.Errorf("base64url_decode empty = %v", []byte(b))
	}
	if s := globals["e3"].(starlark.String); string(s) != "" {
		t.Errorf("hex_encode empty = %q", s)
	}
	if b := globals["d3"].(starlark.Bytes); len(b) != 0 {
		t.Errorf("hex_decode empty = %v", []byte(b))
	}
}

// TestCrypto_ValidKeyLengths ensures AES accepts exactly 16, 24, 32 byte keys.
func TestCrypto_ValidKeyLengths(t *testing.T) {
	for _, sz := range []int{aes.BlockSize, 24, 32} {
		keyHex := hex.EncodeToString(bytes.Repeat([]byte{0xAA}, sz))
		script := `
key = crypto.hex_decode("` + keyHex + `")
iv = crypto.hex_decode("00000000000000000000000000000000")
ct = crypto.aes_encrypt_cbc(key, iv, b"test data here!!")
pt = crypto.aes_decrypt_cbc(key, iv, ct)
`
		globals := execStarlark(t, script)
		pt, ok := globals["pt"].(starlark.Bytes)
		if !ok {
			t.Fatalf("key size %d: pt type = %T", sz, globals["pt"])
		}
		if string(pt) != "test data here!!" {
			t.Errorf("key size %d: pt = %q, want %q", sz, string(pt), "test data here!!")
		}
	}
}
