package aead

import (
	"encoding/binary"

	"github.com/Yawning/chacha20"
	"github.com/Yawning/poly1305"
	"go.artemisc.eu/godium"
)

const (
	Chacha20Poly1305Ietf_KeyBytes  = 32
	Chacha20Poly1305Ietf_NSecBytes = 0
	Chacha20Poly1305Ietf_NPubBytes = 12
	Chacha20Poly1305Ietf_ABytes    = 16
)

var (
	pad0 = make([]byte, 16)
)

type chacha20poly1305ietf struct {
	key []byte
}

// NewChacha20Poly1305Ietf
func NewChacha20Poly1305Ietf(key []byte) (impl godium.AEAD) {
	impl = &chacha20poly1305ietf{
		key: key,
	}
	return
}

func (a *chacha20poly1305ietf) Wipe() {
	godium.Wipe(a.key)
}

// Seal
func (a *chacha20poly1305ietf) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
	block0 := make([]byte, 64)
	slen := make([]byte, 8)
	mlen := len(plain)
	adlen := len(ad)

	// get poly key
	ciph, _ := chacha20.NewCipher(a.key, nonce)
	ciph.KeyStream(block0)

	// create poly
	poly, _ := poly1305.New(block0[:poly1305.KeySize])
	godium.Wipe(block0)

	// update tag
	_, _ = poly.Write(ad)
	_, _ = poly.Write(pad0[:(0x10-adlen)&0xf])

	// encrypt with xor
	cipher = append(dst, plain...)
	_ = ciph.Seek(1)
	ciph.XORKeyStream(cipher, cipher)

	// update tag
	_, _ = poly.Write(cipher)
	_, _ = poly.Write(pad0[:(0x10-mlen)&0xf])

	binary.LittleEndian.PutUint64(slen, uint64(adlen))
	_, _ = poly.Write(slen)
	binary.LittleEndian.PutUint64(slen, uint64(mlen))
	_, _ = poly.Write(slen)

	// add tag
	cipher = poly.Sum(cipher)

	// clear state
	ciph.Reset()
	poly.Clear()

	return
}

// Open
func (a *chacha20poly1305ietf) Open(dst, nonce, cipher, ad []byte) (plain []byte, err error) {
	return
}

func (a *chacha20poly1305ietf) Overhead() (c int) {
	c = Chacha20Poly1305Ietf_ABytes
	return
}

func (a *chacha20poly1305ietf) NonceSize() (c int) {
	c = Chacha20Poly1305Ietf_NPubBytes
	return
}

func (a *chacha20poly1305ietf) KeyBytes() (c int) {
	c = Chacha20Poly1305Ietf_KeyBytes
	return
}

func (a *chacha20poly1305ietf) NSecBytes() (c int) {
	c = Chacha20Poly1305Ietf_NSecBytes
	return
}

func (a *chacha20poly1305ietf) NPubBytes() (c int) {
	c = Chacha20Poly1305Ietf_NPubBytes
	return
}

func (a *chacha20poly1305ietf) ABytes() (c int) {
	c = Chacha20Poly1305Ietf_ABytes
	return
}
