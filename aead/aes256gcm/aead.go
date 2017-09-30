package aes256gcm

import (
	"crypto/aes"
	"crypto/cipher"

	"go.artemisc.eu/godium"
)

const (
	KeyBytes  = 32
	NSecBytes = 0
	NPubBytes = 12
	ABytes    = 16
)

type aeadImpl struct {
	cipher.AEAD
	key []byte
}

//
func New(key []byte) (aesImpl godium.AEAD) {
	block, _ := aes.NewCipher(key)
	impl, _ := cipher.NewGCMWithNonceSize(block, NPubBytes)
	aesImpl = &aeadImpl{
		AEAD: impl,
		key:  key,
	}
	return
}

func (a *aeadImpl) Wipe() {
	godium.Wipe(a.key)
}

func (a *aeadImpl) Overhead() (c int) {
	c = ABytes
	return
}

func (a *aeadImpl) NonceSize() (c int) {
	c = NPubBytes
	return
}

func (a *aeadImpl) KeyBytes() (c int) {
	c = KeyBytes
	return
}

func (a *aeadImpl) NSecBytes() (c int) {
	c = NSecBytes
	return
}

func (a *aeadImpl) NPubBytes() (c int) {
	c = NPubBytes
	return
}

func (a *aeadImpl) ABytes() (c int) {
	c = ABytes
	return
}
