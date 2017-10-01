// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package aead

import (
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
)

const (
	XChacha20Poly1305Ietf_KeyBytes  = 32
	XChacha20Poly1305Ietf_NSecBytes = 0
	XChacha20Poly1305Ietf_NPubBytes = 24
	XChacha20Poly1305Ietf_ABytes    = 16
)

// fixme implement the actual sigma constant for HChacha20
var sigmaConstant []byte = nil

type xchacha20poly1305ietf struct {
	key []byte
}

// NewXChacha20Poly1305Ietf
func NewXChacha20Poly1305Ietf(key []byte) (impl godium.AEAD) {
	impl = &xchacha20poly1305ietf{
		key: key,
	}
	return
}

// Wipe
func (a *xchacha20poly1305ietf) Wipe() {
	godium.Wipe(a.key)
}

// hchacha performs the seal/open common setup of generating a new subkey and
// nonce to be passed to the chacha20poly1305ietf implementation.
func (a *xchacha20poly1305ietf) hchacha(nonce []byte) (aead godium.AEAD, nonce2 []byte) {
	const (
		// aliases
		npubBytes = Chacha20Poly1305Ietf_NPubBytes
		keyBytes  = XChacha20Poly1305Ietf_KeyBytes
	)

	key2 := make([]byte, 0, keyBytes)
	nonce2 = make([]byte, npubBytes)

	key2 = core.HChacha20(key2, nonce2, a.key, sigmaConstant)
	copy(nonce2[4:], nonce[core.HChacha20_InputBytes:core.HChacha20_InputBytes+8])

	aead = NewXChacha20Poly1305Ietf(key2)
	return
}

// Seal
func (a *xchacha20poly1305ietf) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
	aead, nonce2 := a.hchacha(nonce)

	cipher = aead.Seal(dst, nonce2, plain, ad)

	aead.Wipe()
	return
}

// Open
func (a *xchacha20poly1305ietf) Open(dst, nonce, cipher, ad []byte) (plain []byte, err error) {
	aead, nonce2 := a.hchacha(nonce)

	plain, err = aead.Open(dst, nonce2, plain, ad)

	aead.Wipe()
	return
}

func (a *xchacha20poly1305ietf) Overhead() int  { return XChacha20Poly1305Ietf_ABytes }
func (a *xchacha20poly1305ietf) NonceSize() int { return XChacha20Poly1305Ietf_NPubBytes }
func (a *xchacha20poly1305ietf) KeyBytes() int  { return XChacha20Poly1305Ietf_KeyBytes }
func (a *xchacha20poly1305ietf) NSecBytes() int { return XChacha20Poly1305Ietf_NSecBytes }
func (a *xchacha20poly1305ietf) NPubBytes() int { return XChacha20Poly1305Ietf_NPubBytes }
func (a *xchacha20poly1305ietf) ABytes() int    { return XChacha20Poly1305Ietf_ABytes }
