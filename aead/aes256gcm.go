package aead

import (
	"crypto/aes"
	"crypto/cipher"

	"go.artemisc.eu/godium"
)

const (
	Aes256Gcm_KeyBytes  = 32
	Aes256Gcm_NSecBytes = 0
	Aes256Gcm_NPubBytes = 12
	Aes256Gcm_ABytes    = 16
)

type aes256gcm struct {
	cipher.AEAD
	key []byte
}

// NewAes256Gcm
func NewAes256Gcm(key []byte) (aesImpl godium.AEAD) {
	block, _ := aes.NewCipher(key)
	impl, _ := cipher.NewGCMWithNonceSize(block, Aes256Gcm_NPubBytes)
	aesImpl = &aes256gcm{
		AEAD: impl,
		key:  key,
	}
	return
}

// Wipe
func (a *aes256gcm) Wipe() {
	godium.Wipe(a.key)
}

func (a *aes256gcm) Overhead() (c int) {
	c = Aes256Gcm_ABytes
	return
}

func (a *aes256gcm) NonceSize() (c int) {
	c = Aes256Gcm_NPubBytes
	return
}

func (a *aes256gcm) KeyBytes() (c int) {
	c = Aes256Gcm_KeyBytes
	return
}

func (a *aes256gcm) NSecBytes() (c int) {
	c = Aes256Gcm_NSecBytes
	return
}

func (a *aes256gcm) NPubBytes() (c int) {
	c = Aes256Gcm_NPubBytes
	return
}

func (a *aes256gcm) ABytes() (c int) {
	c = Aes256Gcm_ABytes
	return
}
