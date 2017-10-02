// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package secretbox

import (
	"github.com/Yawning/chacha20"
	"github.com/Yawning/poly1305"
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
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
	*chacha20.Cipher
}

// NewXChacha20Poly1305
func NewXChacha20Poly1305(key []byte) (s godium.SecretBox) {
	s = &xchacha20poly1305{
		Key:    godium.Key(key),
		Cipher: nil,
	}
	return
}

// Wipe
func (s *xchacha20poly1305) Wipe() {
	godium.Wipe(s.Key)
	if s.Cipher != nil {
		s.Cipher.Reset()
	}
}

// initCipher
func (s *xchacha20poly1305) initCipher(key, nonce []byte) {
	if s.Cipher == nil {
		s.Cipher, _ = chacha20.NewCipher(key, nonce)
		return
	}
	s.Cipher.ReKey(key, nonce)
}

// SealDetached
func (s xchacha20poly1305) SealDetached(dst, dstMac, nonce, plain []byte) (cipher, mac []byte) {
	block0 := make([]byte, chacha20.BlockSize)
	subkey := make([]byte, 0, chacha20.KeySize)

	mlen := uint64(len(plain))

	cipher = core.AllocDst(dst, mlen)
	mac = core.AllocDst(dstMac, XChacha20Poly1305_MacBytes)

	// get cipher from subkey
	subkey = core.HChacha20(subkey, nonce[:core.HChacha20_InputBytes], s.Key, nil)
	s.initCipher(subkey, nonce[16:24]) // TODO make 16/24 named constants

	// get poly key, and first 32 bytes from xor'ed from the stream
	first := copy(block0[poly1305.Size:], plain)       // put plain into block0, after poly
	s.Cipher.XORKeyStream(block0, block0)              // xor the first block, counter goes to 1
	poly, _ := poly1305.New(block0[:poly1305.KeySize]) // init poly
	copy(cipher, block0[poly1305.Size:])               // copy first bytes of cipher

	if first >= chacha20.BlockSize-poly1305.Size {
		s.Cipher.XORKeyStream(cipher[poly1305.Size:], plain[poly1305.Size:])
	}

	// calculate the poly tag
	poly.Write(cipher)
	mac = poly.Sum(mac[:0])

	godium.Wipe(block0)

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

func (s xchacha20poly1305) Open(dst, nonce, cipher []byte) (plain []byte, err error) {
	mlen := uint64(len(cipher)) - XChacha20Poly1305_MacBytes

	plain = core.AllocDst(dst, mlen)

	return
}

func (s xchacha20poly1305) KeyBytes() int   { return XChacha20Poly1305_KeyBytes }
func (s xchacha20poly1305) MacBytes() int   { return XChacha20Poly1305_MacBytes }
func (s xchacha20poly1305) NonceBytes() int { return XChacha20Poly1305_NonceBytes }
