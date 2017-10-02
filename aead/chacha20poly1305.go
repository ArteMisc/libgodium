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
	Chacha20Poly1305_KeyBytes  = 32
	Chacha20Poly1305_NSecBytes = 0
	Chacha20Poly1305_NPubBytes = 8
	Chacha20Poly1305_ABytes    = 16
)

type chacha20poly1305 struct {
	*chacha20.Cipher
	key []byte
}

// NewChacha20Poly1305
func NewChacha20Poly1305(key []byte) (impl godium.AEAD) {
	impl = &chacha20poly1305{
		Cipher: nil,
		key:    key,
	}
	return
}

// initCipher
func (a *chacha20poly1305) initCipher(key, nonce []byte) {
	if a.Cipher == nil {
		a.Cipher, _ = chacha20.NewCipher(key, nonce)
		return
	}

	_ = a.Cipher.ReKey(key, nonce)
}

// Wipe
func (a *chacha20poly1305) Wipe() {
	godium.Wipe(a.key)
	if a.Cipher != nil {
		a.Cipher.Reset()
	}
}

// Seal
func (a *chacha20poly1305) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
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
	binary.LittleEndian.PutUint64(slen, adlen)
	_, _ = poly.Write(slen)

	// encrypt with xor
	cipher = core.AllocDst(dst, mlen+Chacha20Poly1305_ABytes)
	a.Cipher.XORKeyStream(cipher[:mlen], plain)

	// update tag
	_, _ = poly.Write(cipher[:mlen])
	binary.LittleEndian.PutUint64(slen, mlen)
	_, _ = poly.Write(slen)

	// add tag
	cipher = poly.Sum(cipher[mlen:mlen])

	// clear state
	poly.Clear()

	return
}

// Open
func (a *chacha20poly1305) Open(dst, nonce, cipher, ad []byte) (plain []byte, err error) {
	return
}

func (a *chacha20poly1305) Overhead() int  { return Chacha20Poly1305_ABytes }
func (a *chacha20poly1305) NonceSize() int { return Chacha20Poly1305_NPubBytes }
func (a *chacha20poly1305) KeyBytes() int  { return Chacha20Poly1305_KeyBytes }
func (a *chacha20poly1305) NSecBytes() int { return Chacha20Poly1305_NSecBytes }
func (a *chacha20poly1305) NPubBytes() int { return Chacha20Poly1305_NPubBytes }
func (a *chacha20poly1305) ABytes() int    { return Chacha20Poly1305_ABytes }
