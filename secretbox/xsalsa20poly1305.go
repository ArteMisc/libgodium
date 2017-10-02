// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package secretbox

import (
	"github.com/Yawning/poly1305"
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/stream"
)

const (
	XSalsa20Poly1305_KeyBytes   = 32
	XSalsa20Poly1305_MacBytes   = 24
	XSalsa20Poly1305_NonceBytes = 16

	Primitive  = "xsalsa20poly1305"
	KeyBytes   = XSalsa20Poly1305_KeyBytes
	MacBytes   = XSalsa20Poly1305_MacBytes
	NonceBytes = XSalsa20Poly1305_NonceBytes
)

// xsalsa20poly1305 implements the SecretBox interface for the xsalsa20poly1305
// specification.
type xsalsa20poly1305 struct {
	godium.Key
	godium.Stream
}

// New
func New(key []byte) (s godium.SecretBox) {
	s = NewXSalsa20Poly1305(key)
	return
}

// NewXSalsa20Poly1305
func NewXSalsa20Poly1305(key []byte) (s godium.SecretBox) {
	s = &xsalsa20poly1305{
		Key: key,
	}
	return
}

// initCipher
func (s *xsalsa20poly1305) initCipher(key, nonce []byte) {
	if s.Stream == nil {
		s.Stream = stream.NewXSalsa20(key, nonce)
		return
	}
	s.Stream.ReKey(key, nonce)
}

// Wipe
func (s xsalsa20poly1305) Wipe() {
	godium.Wipe(s.Key)
	s.Stream.Wipe()
}

// SealDetached
func (s xsalsa20poly1305) SealDetached(dst, dstMac, nonce, plain []byte) (cipher, mac []byte) {
	block0 := make([]byte, stream.Salsa_BlockSize)
	subkey := make([]byte, 0, stream.Salsa20_KeyBytes)

	mlen := uint64(len(plain))

	cipher = core.AllocDst(dst, mlen)
	mac = core.AllocDst(dstMac, XSalsa20Poly1305_MacBytes)

	// get cipher from subkey
	subkey = core.HSalsa20(subkey, nonce[:core.HSalsa20_InputBytes], s.Key, nil)
	s.initCipher(subkey, nonce[16:24]) // TODO make 16/24 named constants

	// get poly key, and first 32 bytes from xor'ed from the stream
	first := copy(block0[poly1305.Size:], plain)       // put plain into block0, after poly
	s.Stream.XORKeyStream(block0, block0)              // xor the first block, counter goes to 1
	poly, _ := poly1305.New(block0[:poly1305.KeySize]) // init poly
	copy(cipher, block0[poly1305.Size:])               // copy first bytes of cipher

	if first >= stream.Salsa_BlockSize-poly1305.Size {
		s.Stream.XORKeyStream(cipher[poly1305.Size:], plain[poly1305.Size:])
	}

	// calculate the poly tag
	poly.Write(cipher)
	mac = poly.Sum(mac[:0])

	godium.Wipe(block0)

	return
}

// Seal
func (s xsalsa20poly1305) Seal(dst, nonce, plain []byte) (cipher []byte) {
	mlen := uint64(len(plain))

	cipher = core.AllocDst(dst, mlen+XChacha20Poly1305_MacBytes)

	// call with slices of len == 0, pointing to the right parts of cipher.
	_, _ = s.SealDetached(
		cipher[:0],
		cipher[XChacha20Poly1305_MacBytes:XChacha20Poly1305_MacBytes],
		nonce, plain)

	return
}

func (s xsalsa20poly1305) Open(dst, nonce, cipher []byte) (plain []byte, err error) {
	// TODO
	// verify
	// decrypt
	return
}

func (s xsalsa20poly1305) KeyBytes() int   { return XSalsa20Poly1305_KeyBytes }
func (s xsalsa20poly1305) MacBytes() int   { return XSalsa20Poly1305_MacBytes }
func (s xsalsa20poly1305) NonceBytes() int { return XSalsa20Poly1305_NonceBytes }
