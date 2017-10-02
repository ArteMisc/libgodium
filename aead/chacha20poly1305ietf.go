// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package aead

import (
	"encoding/binary"

	"github.com/Yawning/chacha20"
	"github.com/Yawning/poly1305"
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
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
	*chacha20.Cipher
	key []byte
}

// NewChacha20Poly1305Ietf
func NewChacha20Poly1305Ietf(key []byte) (impl godium.AEAD) {
	impl = &chacha20poly1305ietf{
		Cipher: nil,
		key:    key,
	}
	return
}

// initCipher
func (a *chacha20poly1305ietf) initCipher(key, nonce []byte) {
	if a.Cipher == nil {
		a.Cipher, _ = chacha20.NewCipher(key, nonce)
		return
	}

	_ = a.Cipher.ReKey(key, nonce)
}

// Wipe
func (a *chacha20poly1305ietf) Wipe() {
	godium.Wipe(a.key)
	if a.Cipher != nil {
		a.Cipher.Reset()
	}
}

// Seal
func (a *chacha20poly1305ietf) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
	block0 := make([]byte, chacha20.BlockSize)
	slen := make([]byte, 8)

	mlen := uint64(len(plain))
	adlen := uint64(len(ad))

	// get poly key
	a.initCipher(a.key, nonce)
	a.Cipher.KeyStream(block0)

	// create poly
	poly, _ := poly1305.New(block0[:poly1305.KeySize])
	godium.Wipe(block0)

	// update tag
	_, _ = poly.Write(ad)
	_, _ = poly.Write(pad0[:(0x10-adlen)&0xf])

	// encrypt with xor
	cipher = core.AllocDst(dst, mlen+Chacha20Poly1305Ietf_ABytes)
	a.Cipher.XORKeyStream(cipher[:mlen], plain)

	// update tag
	_, _ = poly.Write(cipher)
	_, _ = poly.Write(pad0[:(0x10-mlen)&0xf])

	binary.LittleEndian.PutUint64(slen, adlen)
	_, _ = poly.Write(slen)
	binary.LittleEndian.PutUint64(slen, mlen)
	_, _ = poly.Write(slen)

	// add tag
	cipher = poly.Sum(cipher[mlen:mlen])

	// clear state
	poly.Clear()

	return
}

// Open
func (a *chacha20poly1305ietf) Open(dst, nonce, cipher, ad []byte) (plain []byte, err error) {
	return
}

func (a *chacha20poly1305ietf) Overhead() int  { return Chacha20Poly1305Ietf_ABytes }
func (a *chacha20poly1305ietf) NonceSize() int { return Chacha20Poly1305Ietf_NPubBytes }
func (a *chacha20poly1305ietf) KeyBytes() int  { return Chacha20Poly1305Ietf_KeyBytes }
func (a *chacha20poly1305ietf) NSecBytes() int { return Chacha20Poly1305Ietf_NSecBytes }
func (a *chacha20poly1305ietf) NPubBytes() int { return Chacha20Poly1305Ietf_NPubBytes }
func (a *chacha20poly1305ietf) ABytes() int    { return Chacha20Poly1305Ietf_ABytes }
