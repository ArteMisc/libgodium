// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package stream

import (
	"github.com/Yawning/chacha20"
	"go.artemisc.eu/godium"
)

const (
	Chacha20_KeyBytes   = 32
	Chacha20_NonceBytes = 8

	Chacha20Ietf_KeyBytes   = 32
	Chacha20Ietf_NonceBytes = 12

	XChacha20_KeyBytes   = 32
	XChacha20_NonceBytes = 24
)

// chacha20 implements the chacha20, chacha20ietf and xchacha20 variants of the
// chacha20 stream cipher.
type chacha20Impl struct {
	*chacha20.Cipher
	key   []byte
	nonce []byte
}

// NewChacha20
func NewChacha20(key, nonce []byte) (s godium.Stream) {
	c, _ := chacha20.NewCipher(key, nonce)
	s = &chacha20Impl{
		Cipher: c,
		key:    key[:Chacha20_KeyBytes],
		nonce:  nonce[:Chacha20_NonceBytes],
	}
	return
}

// NewChacha20Ietf
func NewChacha20Ietf(key, nonce []byte) (s godium.Stream) {
	c, _ := chacha20.NewCipher(key, nonce)
	s = &chacha20Impl{
		Cipher: c,
		key:    key[:Chacha20Ietf_KeyBytes],
		nonce:  nonce[:Chacha20Ietf_NonceBytes],
	}
	return
}

// NewXChacha20
func NewXChacha20(key, nonce []byte) (s godium.Stream) {
	c, _ := chacha20.NewCipher(key, nonce)
	s = &chacha20Impl{
		Cipher: c,
		key:    key[:XChacha20_KeyBytes],
		nonce:  nonce[:XChacha20_NonceBytes],
	}
	return
}

func (s *chacha20Impl) Wipe() {
	s.Cipher.Reset()
}

func (s *chacha20Impl) ReKey(key, nonce []byte) {
	s.ReKey(key, nonce)
	s.key = key[:len(s.key)]
	s.nonce = nonce[:len(s.nonce)]
}

func (s *chacha20Impl) XORKeyStream(dst, src []byte) {
	s.Cipher.XORKeyStream(dst, src)
}

func (s *chacha20Impl) KeyStream(dst []byte) {
	s.Cipher.KeyStream(dst)
}

func (s *chacha20Impl) Seek(counter uint64) (st godium.Stream) {
	st = s
	_ = s.Cipher.Seek(counter)
	return
}

func (s *chacha20Impl) KeyBytes() int   { return len(s.key) }
func (s *chacha20Impl) NonceBytes() int { return len(s.nonce) }
