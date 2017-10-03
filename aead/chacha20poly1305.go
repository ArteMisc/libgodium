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
	Chacha20Poly1305_KeyBytes  = 32
	Chacha20Poly1305_NSecBytes = 0
	Chacha20Poly1305_NPubBytes = 8
	Chacha20Poly1305_ABytes    = 16
)

type chacha20poly1305 struct {
	godium.Key
	godium.Stream
	godium.OneTimeAuth
}

// NewChacha20Poly1305
func NewChacha20Poly1305(key []byte) (impl godium.AEAD) {
	impl = &chacha20poly1305{
		Key: core.Copy(key, Chacha20Poly1305_KeyBytes),
	}
	return
}

// initAead
func (a *chacha20poly1305) initAead(key, nonce []byte) {
	var block0 [stream.Chacha20_BlockBytes]byte

	if a.Stream == nil {
		a.Stream = stream.NewChacha20(key, nonce)
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
func (a *chacha20poly1305) Wipe() {
	godium.Wipe(a.Key)
	if a.Stream != nil {
		a.Stream.Wipe()
	}
	if a.OneTimeAuth != nil {
		a.OneTimeAuth.Wipe()
	}
}

func (a *chacha20poly1305) SealDetached(dst, dstMac, nonce, plain, ad []byte) (cipher, mac []byte) {
	var slen [8]byte

	mlen := uint64(len(plain))
	adlen := uint64(len(ad))

	cipher = core.AllocDst(dst, mlen)
	mac = core.AllocDst(dstMac, Chacha20Poly1305_ABytes)

	a.initAead(a.Key, nonce)

	// update tag
	a.OneTimeAuth.Write(ad)
	binary.LittleEndian.PutUint64(slen[:], adlen)
	a.OneTimeAuth.Write(slen[:])

	// encrypt with xor
	a.Stream.XORKeyStream(cipher, plain)

	// update tag
	a.OneTimeAuth.Write(cipher)
	binary.LittleEndian.PutUint64(slen[:], mlen)
	a.OneTimeAuth.Write(slen[:])

	// add tag
	a.OneTimeAuth.Sum(mac[:0])

	return
}

// Seal
func (a *chacha20poly1305) Seal(dst, nonce, plain, ad []byte) (cipher []byte) {
	mlen := uint64(len(plain))
	cipher = core.AllocDst(dst, mlen+Chacha20Poly1305_ABytes)

	// call with slices of len == 0, pointing to the right parts of cipher.
	_, _ = a.SealDetached(cipher[0:0], cipher[mlen:mlen], nonce, plain, ad)
	return
}

// OpenDetached
func (a *chacha20poly1305) OpenDetached(dst, nonce, cipher, mac, ad []byte) (plain []byte, err error) {
	var slen [8]byte

	mlen := uint64(len(cipher))
	adlen := uint64(len(ad))

	plain = core.AllocDst(dst, mlen)

	a.initAead(a.Key, nonce)

	// update tag
	a.OneTimeAuth.Write(ad)
	binary.LittleEndian.PutUint64(slen[:], adlen)
	a.OneTimeAuth.Write(slen[:])

	a.OneTimeAuth.Write(cipher)
	binary.LittleEndian.PutUint64(slen[:], mlen)
	a.OneTimeAuth.Write(slen[:])

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
func (a *chacha20poly1305) Open(dst, nonce, cipher, ad []byte) (plain []byte, err error) {
	mlen := uint64(len(cipher) - Chacha20Poly1305_ABytes)
	plain = core.AllocDst(dst, mlen)

	// call with slices of len == 0, pointing to the right parts of cipher.
	_, err = a.OpenDetached(plain, nonce, cipher[:mlen], cipher[mlen:], ad)
	return
}

func (a *chacha20poly1305) Overhead() int  { return Chacha20Poly1305_ABytes }
func (a *chacha20poly1305) NonceSize() int { return Chacha20Poly1305_NPubBytes }
func (a *chacha20poly1305) KeyBytes() int  { return Chacha20Poly1305_KeyBytes }
func (a *chacha20poly1305) NSecBytes() int { return Chacha20Poly1305_NSecBytes }
func (a *chacha20poly1305) NPubBytes() int { return Chacha20Poly1305_NPubBytes }
func (a *chacha20poly1305) ABytes() int    { return Chacha20Poly1305_ABytes }
