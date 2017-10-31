// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package aead

import (
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/internal"
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
	godium.Key
	*chacha20poly1305ietf
}

// NewXChacha20Poly1305Ietf
func NewXChacha20Poly1305Ietf(key []byte) (impl godium.AEAD) {
	impl = &xchacha20poly1305ietf{
		Key:                  internal.Copy(key, XChacha20Poly1305Ietf_KeyBytes),
		chacha20poly1305ietf: new(chacha20poly1305ietf),
	}
	return
}

// Wipe
func (a *xchacha20poly1305ietf) Wipe() {
	godium.Wipe(a.Key)
	a.chacha20poly1305ietf.Wipe()
}

// initAead performs the seal/open common setup of generating a new subkey and
// nonce to be passed to the chacha20poly1305ietf implementation.
func (a *xchacha20poly1305ietf) initAead(nonce []byte) (nonce2 []byte) {
	const (
		// aliases
		npubBytes = Chacha20Poly1305Ietf_NPubBytes
		keyBytes  = XChacha20Poly1305Ietf_KeyBytes
	)

	key2 := make([]byte, 0, keyBytes)
	nonce2 = make([]byte, npubBytes)

	key2 = core.HChacha20(key2, nonce2, a.Key, sigmaConstant)
	copy(nonce2[4:], nonce[core.HChacha20_InputBytes:core.HChacha20_InputBytes+8])

	a.chacha20poly1305ietf.Key = key2
	return
}

// Seal
func (a *xchacha20poly1305ietf) SealDetached(dst, dstMac, nonce, plain, ad []byte) (cipher, mac []byte) {
	nonce2 := a.initAead(nonce)

	cipher, mac = a.chacha20poly1305ietf.SealDetached(dst, dstMac, nonce2, plain, ad)

	godium.Wipe(a.chacha20poly1305ietf.Key)
	return
}

// Seal
func (a *xchacha20poly1305ietf) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
	nonce2 := a.initAead(nonce)

	cipher = a.chacha20poly1305ietf.Seal(dst, nonce2, plain, ad)

	godium.Wipe(a.chacha20poly1305ietf.Key)
	return
}

// OpenDetached
func (a *xchacha20poly1305ietf) OpenDetached(dst, nonce, cipher, mac, ad []byte) (plain []byte, err error) {
	nonce2 := a.initAead(nonce)

	plain, err = a.chacha20poly1305ietf.OpenDetached(dst, nonce2, cipher, mac, ad)

	godium.Wipe(a.chacha20poly1305ietf.Key)
	return
}

// Open
func (a *xchacha20poly1305ietf) Open(dst, nonce, cipher, ad []byte) (plain []byte, err error) {
	nonce2 := a.initAead(nonce)

	plain, err = a.chacha20poly1305ietf.Open(dst, nonce2, cipher, ad)

	godium.Wipe(a.chacha20poly1305ietf.Key)
	return
}

func (a *xchacha20poly1305ietf) Overhead() int  { return XChacha20Poly1305Ietf_ABytes }
func (a *xchacha20poly1305ietf) NonceSize() int { return XChacha20Poly1305Ietf_NPubBytes }
func (a *xchacha20poly1305ietf) KeyBytes() int  { return XChacha20Poly1305Ietf_KeyBytes }
func (a *xchacha20poly1305ietf) NSecBytes() int { return XChacha20Poly1305Ietf_NSecBytes }
func (a *xchacha20poly1305ietf) NPubBytes() int { return XChacha20Poly1305Ietf_NPubBytes }
func (a *xchacha20poly1305ietf) ABytes() int    { return XChacha20Poly1305Ietf_ABytes }
