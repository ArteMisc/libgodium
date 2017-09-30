package xchacha20poly1305ietf

import (
	"go.artemisc.eu/godium"
	ietf "go.artemisc.eu/godium/aead/chacha20poly1305ietf"
	"go.artemisc.eu/godium/core/hchacha"
)

const (
	KeyBytes  = 32
	NSecBytes = 0
	NPubBytes = 24
	ABytes    = 16
)

// fixme implement the actual sigma constant for HChacha20
var sigmaConstant []byte = nil

type aeadImpl struct {
	key []byte
}

func New(key []byte) (impl godium.AEAD) {
	impl = &aeadImpl{
		key:  key,
	}
	return
}

// Wipe
func (a *aeadImpl) Wipe() {
	godium.Wipe(a.key)
}

// hchacha performs the seal/open common setup of generating a new subkey and
// nonce to be passed to the chacha20poly1305ietf implementation.
func (a *aeadImpl) hchacha(nonce []byte) (aead godium.AEAD, nonce2 []byte) {
	key2 := make([]byte, 0, KeyBytes)
	nonce2 = make([]byte, ietf.NPubBytes)

	key2 = hchacha.HChacha20(key2, nonce2, a.key, sigmaConstant)
	copy(nonce2[4:], nonce[hchacha.InputBytes:hchacha.InputBytes+8])

	aead = ietf.New(key2)
	return
}

// Seal
func (a *aeadImpl) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
	aead, nonce2 := a.hchacha(nonce)

	cipher = aead.Seal(dst, nonce2, plain, ad)

	aead.Wipe()
	return
}

// Open
func (a *aeadImpl) Open(dst, nonce, cipher, ad []byte) (plain []byte, err error) {
	aead, nonce2 := a.hchacha(nonce)

	plain, err = aead.Open(dst, nonce2, plain, ad)

	aead.Wipe()
	return
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
