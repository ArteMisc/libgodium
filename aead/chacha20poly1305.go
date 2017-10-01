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
)

const (
	Chacha20Poly1305_KeyBytes  = 32
	Chacha20Poly1305_NSecBytes = 0
	Chacha20Poly1305_NPubBytes = 8
	Chacha20Poly1305_ABytes    = 16
)

type chacha20poly1305 struct {
	key []byte
}

// NewChacha20Poly1305
func NewChacha20Poly1305(key []byte) (impl godium.AEAD) {
	impl = &chacha20poly1305{
		key: key,
	}
	return
}

// Wipe
func (a *chacha20poly1305) Wipe() {
	godium.Wipe(a.key)
}

// Seal
func (a *chacha20poly1305) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
	block0 := make([]byte, 64)
	slen := make([]byte, 8)

	// get poly key
	ciph, _ := chacha20.NewCipher(a.key, nonce)
	ciph.KeyStream(block0)

	// create poly
	poly, _ := poly1305.New(block0[:poly1305.KeySize])
	godium.Wipe(block0)

	// update tag
	_, _ = poly.Write(ad)
	binary.LittleEndian.PutUint64(slen, uint64(len(ad)))
	_, _ = poly.Write(slen)

	// encrypt with xor
	cipher = append(dst, plain...)
	_ = ciph.Seek(1)
	ciph.XORKeyStream(cipher, cipher)

	// update tag
	_, _ = poly.Write(cipher)
	binary.LittleEndian.PutUint64(slen, uint64(len(cipher)))
	_, _ = poly.Write(slen)

	// add tag
	cipher = poly.Sum(cipher)

	// clear state
	ciph.Reset()
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
