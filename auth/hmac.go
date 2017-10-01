package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"go.artemisc.eu/godium"
)

const (
	HmacSha256_Bytes    = 32
	HmacSha256_KeyBytes = 32

	HmacSha512_Bytes    = 64
	HmacSha512_KeyBytes = 32

	HmacSha512256_Bytes    = 32
	HmacSha512256_KeyBytes = 32
)

// hmacImpl implements the godium.Auth API on top of golang's own hash and hmac
// implementations.
type hmacImpl struct {
	hash.Hash
	key []byte
}

// NewHmacSha256
func NewHmacSha256(key []byte) (auth godium.Auth) {
	auth = &hmacImpl{
		Hash: hmac.New(sha256.New, key),
		key:  key,
	}
	return
}

// NewHmacSha512
func NewHmacSha512(key []byte) (auth godium.Auth) {
	auth = &hmacImpl{
		Hash: hmac.New(sha512.New, key),
		key:  key,
	}
	return
}

// NewHmacSha512256
func NewHmacSha512256(key []byte) (auth godium.Auth) {
	auth = &hmacImpl{
		Hash: hmac.New(sha512.New512_256, key),
		key:  key,
	}
	return
}

// Wipe
func (h *hmacImpl) Wipe() {
	godium.Wipe(h.key)
}

// Verify
func (h *hmacImpl) Verify(expect []byte) (matches bool) {
	matches = hmac.Equal(h.Sum(nil), expect)
	return
}
