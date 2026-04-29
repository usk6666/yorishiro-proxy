package pluginv2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// newCryptoModule creates the predeclared "crypto" module available to scripts.
// It exposes pure cryptographic functions wrapping Go's standard library.
func newCryptoModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "crypto",
		Members: starlark.StringDict{
			// Hash functions
			"md5":    starlark.NewBuiltin("crypto.md5", cryptoHash(md5.New)),
			"sha1":   starlark.NewBuiltin("crypto.sha1", cryptoHash(sha1.New)),
			"sha256": starlark.NewBuiltin("crypto.sha256", cryptoHash(sha256.New)),
			"sha512": starlark.NewBuiltin("crypto.sha512", cryptoHash(sha512.New)),

			// HMAC functions
			"hmac_md5":    starlark.NewBuiltin("crypto.hmac_md5", cryptoHMAC(md5.New)),
			"hmac_sha1":   starlark.NewBuiltin("crypto.hmac_sha1", cryptoHMAC(sha1.New)),
			"hmac_sha256": starlark.NewBuiltin("crypto.hmac_sha256", cryptoHMAC(sha256.New)),
			"hmac_sha512": starlark.NewBuiltin("crypto.hmac_sha512", cryptoHMAC(sha512.New)),

			// AES functions
			"aes_encrypt_cbc": starlark.NewBuiltin("crypto.aes_encrypt_cbc", aesEncryptCBC),
			"aes_decrypt_cbc": starlark.NewBuiltin("crypto.aes_decrypt_cbc", aesDecryptCBC),
			"aes_encrypt_gcm": starlark.NewBuiltin("crypto.aes_encrypt_gcm", aesEncryptGCM),
			"aes_decrypt_gcm": starlark.NewBuiltin("crypto.aes_decrypt_gcm", aesDecryptGCM),

			// Encoding functions
			"hex_encode":       starlark.NewBuiltin("crypto.hex_encode", hexEncode),
			"hex_decode":       starlark.NewBuiltin("crypto.hex_decode", hexDecode),
			"base64_encode":    starlark.NewBuiltin("crypto.base64_encode", base64Encode),
			"base64_decode":    starlark.NewBuiltin("crypto.base64_decode", base64Decode),
			"base64url_encode": starlark.NewBuiltin("crypto.base64url_encode", base64URLEncode),
			"base64url_decode": starlark.NewBuiltin("crypto.base64url_decode", base64URLDecode),
		},
	}
}

// cryptoHash returns a Starlark built-in that computes a hash digest.
// The returned function accepts a single bytes argument and returns bytes.
func cryptoHash(newHash func() hash.Hash) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var data starlark.Bytes
		if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &data); err != nil {
			return nil, err
		}
		h := newHash()
		h.Write([]byte(data))
		return starlark.Bytes(h.Sum(nil)), nil
	}
}

// cryptoHMAC returns a Starlark built-in that computes an HMAC digest.
// The returned function accepts key (bytes) and message (bytes) and returns bytes.
func cryptoHMAC(newHash func() hash.Hash) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var key, message starlark.Bytes
		if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &key, &message); err != nil {
			return nil, err
		}
		mac := hmac.New(newHash, []byte(key))
		mac.Write([]byte(message))
		return starlark.Bytes(mac.Sum(nil)), nil
	}
}

// aesEncryptCBC implements AES-CBC encryption with PKCS#7 padding.
func aesEncryptCBC(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, iv, plaintext starlark.Bytes
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 3, &key, &iv, &plaintext); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("%s: iv must be %d bytes, got %d", fn.Name(), aes.BlockSize, len(iv))
	}

	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, padded)

	return starlark.Bytes(ciphertext), nil
}

// aesDecryptCBC implements AES-CBC decryption with PKCS#7 unpadding.
func aesDecryptCBC(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, iv, ciphertext starlark.Bytes
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 3, &key, &iv, &ciphertext); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("%s: iv must be %d bytes, got %d", fn.Name(), aes.BlockSize, len(iv))
	}

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%s: ciphertext length must be a positive multiple of %d, got %d", fn.Name(), aes.BlockSize, len(ciphertext))
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(plaintext, []byte(ciphertext))

	unpadded, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	return starlark.Bytes(unpadded), nil
}

// aesEncryptGCM implements AES-GCM authenticated encryption.
// Returns ciphertext with the authentication tag appended.
func aesEncryptGCM(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, nonce, plaintext, aad starlark.Bytes
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 4, &key, &nonce, &plaintext, &aad); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	if len(nonce) != aesGCM.NonceSize() {
		return nil, fmt.Errorf("%s: nonce must be %d bytes, got %d", fn.Name(), aesGCM.NonceSize(), len(nonce))
	}

	var aadBytes []byte
	if len(aad) > 0 {
		aadBytes = []byte(aad)
	}

	ciphertext := aesGCM.Seal(nil, []byte(nonce), []byte(plaintext), aadBytes)
	return starlark.Bytes(ciphertext), nil
}

// aesDecryptGCM implements AES-GCM authenticated decryption.
// The ciphertext is expected to have the authentication tag appended.
func aesDecryptGCM(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, nonce, ciphertext, aad starlark.Bytes
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 4, &key, &nonce, &ciphertext, &aad); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	if len(nonce) != aesGCM.NonceSize() {
		return nil, fmt.Errorf("%s: nonce must be %d bytes, got %d", fn.Name(), aesGCM.NonceSize(), len(nonce))
	}

	var aadBytes []byte
	if len(aad) > 0 {
		aadBytes = []byte(aad)
	}

	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), aadBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	return starlark.Bytes(plaintext), nil
}

// hexEncode encodes bytes to a hex string.
func hexEncode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Bytes
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &data); err != nil {
		return nil, err
	}
	return starlark.String(hex.EncodeToString([]byte(data))), nil
}

// hexDecode decodes a hex string to bytes.
func hexDecode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &s); err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(string(s))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}
	return starlark.Bytes(decoded), nil
}

// base64Encode encodes bytes to a standard base64 string.
func base64Encode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Bytes
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &data); err != nil {
		return nil, err
	}
	return starlark.String(base64.StdEncoding.EncodeToString([]byte(data))), nil
}

// base64Decode decodes a standard base64 string to bytes.
func base64Decode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &s); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}
	return starlark.Bytes(decoded), nil
}

// base64URLEncode encodes bytes to a URL-safe base64 string without padding.
func base64URLEncode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Bytes
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &data); err != nil {
		return nil, err
	}
	return starlark.String(base64.RawURLEncoding.EncodeToString([]byte(data))), nil
}

// base64URLDecode decodes a URL-safe base64 string (without padding) to bytes.
func base64URLDecode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &s); err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(s))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}
	return starlark.Bytes(decoded), nil
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding from data.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7 unpad: empty data")
	}
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7 unpad: data length %d is not a multiple of block size %d", len(data), blockSize)
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("pkcs7 unpad: invalid padding value %d", padding)
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("pkcs7 unpad: invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}
