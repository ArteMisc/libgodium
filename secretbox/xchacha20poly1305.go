// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package secretbox

import (
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/onetimeauth"
	"go.artemisc.eu/godium/stream"
)

const (
	XChacha20Poly1305_KeyBytes   = 32
	XChacha20Poly1305_MacBytes   = 24
	XChacha20Poly1305_NonceBytes = 16
)

// xchacha20poly1305 implements the SecretBox interface for the xchacha20poly1305
// specification.
type xchacha20poly1305 struct {
	godium.Key
	godium.Stream
	godium.OneTimeAuth
}

// NewXChacha20Poly1305
func NewXChacha20Poly1305(key []byte) (s godium.SecretBox) {
	s = &xchacha20poly1305{
		Key: godium.Key(key),
	}
	return
}

// Wipe
func (s *xchacha20poly1305) Wipe() {
	godium.Wipe(s.Key)
	if s.Stream != nil {
		s.Stream.Wipe()
	}
	if s.OneTimeAuth != nil {
		s.OneTimeAuth.Wipe()
	}
}

// initStream
func (s *xchacha20poly1305) initStream(key, nonce []byte) {
	var polyKey [onetimeauth.Poly1305_KeyBytes]byte

	if s.Stream == nil {
		s.Stream = stream.NewXChacha20(key, nonce)
	} else {
		s.Stream.ReKey(key, nonce)
	}

	s.Stream.KeyStream(polyKey[:])

	if s.OneTimeAuth == nil {
		s.OneTimeAuth = onetimeauth.NewPoly1305(polyKey[:])
	} else {
		s.OneTimeAuth.ReKey(polyKey[:])
	}

	godium.Wipe(polyKey[:])
}

// SealDetached
func (s xchacha20poly1305) SealDetached(dst, dstMac, nonce, plain []byte) (cipher, mac []byte) {
	subKey := make([]byte, 0, stream.XChacha20_KeyBytes)
	cipher = core.AllocDst(dst, uint64(len(plain)))
	mac = core.AllocDst(dstMac, XChacha20Poly1305_MacBytes)

	// get cipher from subKey
	s.initStream(subKey, nonce[:XChacha20Poly1305_NonceBytes])

	s.Stream.XORKeyStream(cipher[XChacha20Poly1305_MacBytes:], plain)

	// calculate the poly tag
	s.OneTimeAuth.Write(cipher)
	s.OneTimeAuth.Sum(mac[:0])

	godium.Wipe(subKey)
	return
}

// Seal
func (s xchacha20poly1305) Seal(dst, nonce, plain []byte) (cipher []byte) {
	mlen := uint64(len(plain))

	cipher = core.AllocDst(dst, mlen+XChacha20Poly1305_MacBytes)

	// call with slices of len == 0, pointing to the right parts of cipher.
	_, _ = s.SealDetached(
		cipher[:0],
		cipher[XChacha20Poly1305_MacBytes:XChacha20Poly1305_MacBytes],
		nonce, plain)

	return
}

// OpenDetached
func (s *xchacha20poly1305) OpenDetached(dst, nonce, mac, cipher []byte) (plain []byte, err error) {
	subKey := make([]byte, 0, stream.XChacha20_KeyBytes)
	cipher = core.AllocDst(dst, uint64(len(plain)))

	// get cipher from subKey
	s.initStream(subKey, nonce[:XChacha20Poly1305_NonceBytes])

	// calculate the poly tag
	s.OneTimeAuth.Write(cipher)
	if !s.OneTimeAuth.Verify(mac) {
		err = godium.ErrForgedOrCorrupted
		return
	}

	s.Stream.XORKeyStream(cipher[XChacha20Poly1305_MacBytes:], plain)

	godium.Wipe(subKey)
	return
}

func (s xchacha20poly1305) Open(dst, nonce, cipher []byte) (plain []byte, err error) {
	mlen := uint64(len(cipher)) - XChacha20Poly1305_MacBytes
	plain = core.AllocDst(dst, mlen)

	// call with slices of len == 0, pointing to the right parts of the plain
	plain, err = s.OpenDetached(plain[:0], nonce,
		cipher[:XChacha20Poly1305_MacBytes],
		cipher[XChacha20Poly1305_MacBytes:])
	return
}

func (s xchacha20poly1305) KeyBytes() int   { return XChacha20Poly1305_KeyBytes }
func (s xchacha20poly1305) MacBytes() int   { return XChacha20Poly1305_MacBytes }
func (s xchacha20poly1305) NonceBytes() int { return XChacha20Poly1305_NonceBytes }
