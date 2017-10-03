// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package aead

import (
	"encoding/binary"

	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/onetimeauth"
	"go.artemisc.eu/godium/stream"
)

const (
	Chacha20Poly1305Ietf_KeyBytes  = 32
	Chacha20Poly1305Ietf_NSecBytes = 0
	Chacha20Poly1305Ietf_NPubBytes = 12
	Chacha20Poly1305Ietf_ABytes    = 16
)

var (
	pad0 [16]byte
)

type chacha20poly1305ietf struct {
	godium.Key
	godium.Stream
	godium.OneTimeAuth
}

// NewChacha20Poly1305Ietf
func NewChacha20Poly1305Ietf(key []byte) (impl godium.AEAD) {
	impl = &chacha20poly1305ietf{
		Key: core.Copy(key, Chacha20Poly1305Ietf_KeyBytes),
	}
	return
}

// initAead
func (a *chacha20poly1305ietf) initAead(key, nonce []byte) {
	var block0 [stream.Chacha20Ietf_BlockBytes]byte

	if a.Stream == nil {
		a.Stream = stream.NewChacha20Ietf(key, nonce)
	} else {
		a.Stream.ReKey(key, nonce)
	}

	if a.OneTimeAuth == nil {
		a.OneTimeAuth = onetimeauth.NewPoly1305(block0[:onetimeauth.Poly1305_KeyBytes])
	} else {
		a.OneTimeAuth.ReKey(block0[:onetimeauth.Poly1305_KeyBytes])
	}

	godium.Wipe(block0[:])
}

// Wipe
func (a *chacha20poly1305ietf) Wipe() {
	godium.Wipe(a.Key)

	if a.Stream != nil {
		a.Stream.Wipe()
	}
	if a.OneTimeAuth != nil {
		a.OneTimeAuth.Wipe()
	}
}

func (a *chacha20poly1305ietf) SealDetached(dst, dstMac, nonce, plain, ad []byte) (cipher, mac []byte) {
	slen := make([]byte, 8)

	mlen := uint64(len(plain))
	adlen := uint64(len(ad))

	cipher = core.AllocDst(dst, mlen)
	mac = core.AllocDst(dstMac, Chacha20Poly1305Ietf_ABytes)

	a.initAead(a.Key, nonce)

	// update tag
	a.OneTimeAuth.Write(ad)
	a.OneTimeAuth.Write(pad0[:(0x10-adlen)&0xf])

	// encrypt with xor
	a.Stream.XORKeyStream(cipher[:mlen], plain)

	// update tag
	a.OneTimeAuth.Write(cipher)
	a.OneTimeAuth.Write(pad0[:(0x10-mlen)&0xf])

	binary.LittleEndian.PutUint64(slen, adlen)
	a.OneTimeAuth.Write(slen)
	binary.LittleEndian.PutUint64(slen, mlen)
	a.OneTimeAuth.Write(slen)

	// add tag
	a.OneTimeAuth.Sum(mac[:0])

	return
}

// Seal
func (a *chacha20poly1305ietf) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
	mlen := uint64(len(plain))
	cipher = core.AllocDst(dst, mlen+Chacha20Poly1305_ABytes)

	// call with slices of len == 0, pointing to the right parts of cipher.
	_, _ = a.SealDetached(cipher[0:0], cipher[mlen:mlen], nonce, plain, ad)
	return
}

// OpenDetached
func (a *chacha20poly1305ietf) OpenDetached(dst, nonce, cipher, mac, ad []byte) (plain []byte, err error) {
	slen := make([]byte, 8)

	mlen := uint64(len(cipher))
	adlen := uint64(len(ad))

	plain = core.AllocDst(dst, mlen)

	a.initAead(a.Key, nonce)

	// update tag
	a.OneTimeAuth.Write(ad)
	a.OneTimeAuth.Write(pad0[:(0x10-adlen)&0xf])

	a.OneTimeAuth.Write(cipher)
	a.OneTimeAuth.Write(pad0[:(0x10-mlen)&0xf])

	binary.LittleEndian.PutUint64(slen, adlen)
	a.OneTimeAuth.Write(slen)
	binary.LittleEndian.PutUint64(slen, mlen)
	a.OneTimeAuth.Write(slen)

	// verify tag
	if !a.OneTimeAuth.Verify(mac) {
		err = godium.ErrForgedOrCorrupted
		return
	}

	// encrypt with xor
	a.Stream.XORKeyStream(plain, cipher)

	return
}

// Open
func (a *chacha20poly1305ietf) Open(dst, nonce, cipher, ad []byte) (plain []byte, err error) {
	mlen := uint64(len(cipher) - Chacha20Poly1305Ietf_ABytes)
	plain = core.AllocDst(dst, mlen)

	_, err = a.OpenDetached(plain[:0], nonce, cipher[:mlen], cipher[mlen:], ad)
	return
}

func (a *chacha20poly1305ietf) Overhead() int  { return Chacha20Poly1305Ietf_ABytes }
func (a *chacha20poly1305ietf) NonceSize() int { return Chacha20Poly1305Ietf_NPubBytes }
func (a *chacha20poly1305ietf) KeyBytes() int  { return Chacha20Poly1305Ietf_KeyBytes }
func (a *chacha20poly1305ietf) NSecBytes() int { return Chacha20Poly1305Ietf_NSecBytes }
func (a *chacha20poly1305ietf) NPubBytes() int { return Chacha20Poly1305Ietf_NPubBytes }
func (a *chacha20poly1305ietf) ABytes() int    { return Chacha20Poly1305Ietf_ABytes }
