// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package stream

import (
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"encoding/binary"
)

const (
	Salsa20_KeyBytes   = 32
	Salsa20_NonceBytes = 16

	XSalsa20_KeyBytes   = 32
	XSalsa20_NonceBytes = 24

	Salsa_BlockSize = 64
)

type salsa20Impl struct {
	key         [Salsa20_KeyBytes]byte
	block       [Salsa_BlockSize]byte
	counter     [16]byte
	blockOffset int
	isXSalsa    bool
}

// NewSalsa20
func NewSalsa20(key, nonce []byte) (s godium.Stream) {
	s = new(salsa20Impl)
	s.ReKey(key, nonce[:Salsa20_NonceBytes])
	return
}

// NewXSalsa20
func NewXSalsa20(key, nonce []byte) (s godium.Stream) {
	s = new(salsa20Impl)
	s.ReKey(key, nonce[:XSalsa20_NonceBytes])
	return
}

// incrCounter
func (s *salsa20Impl) incrCounter() {
	u := uint32(1)
	for i := 8; i < 16; i++ {
		u += uint32(s.counter[i])
		s.counter[i] = byte(u)
		u >>= 8
	}
}

// nextState
func (s *salsa20Impl) nextState() {
	// get the buffer
	core.Salsa20(&s.block, &s.counter, &s.key, &core.Salsa20Sigma)
	// increment the counter
	s.incrCounter()
}

// Wipe
func (s *salsa20Impl) Wipe() {
	godium.Wipe(s.key[:])
	godium.Wipe(s.counter[:])
}

// ReKey
func (s *salsa20Impl) ReKey(key, nonce []byte) {
	s.isXSalsa = len(nonce) >= XSalsa20_NonceBytes

	if s.isXSalsa {
		key = core.HSalsa20(nil, nonce, key, nil)
		nonce = nonce[16:24]
	}

	copy(s.key[:], key)
	copy(s.counter[:], nonce[:8])
	for i := 8; i < 16; i++ {
		s.counter[i] = 0
	}
}

// KeyStream
func (s *salsa20Impl) KeyStream(dst []byte) {
	// first block
	if s.blockOffset > 0 {
		n := copy(dst, s.block[s.blockOffset:])
		dst = dst[n:]

		s.blockOffset += n
	}

	if s.blockOffset == Salsa_BlockSize {
		s.incrCounter()
		s.blockOffset = 0
	}

	// rest of the blocks
	for len(dst) > 0 {
		s.nextState()
		n := copy(dst, s.block[:])

		if n < Salsa_BlockSize {
			s.blockOffset = n
			return
		}

		dst = dst[Salsa_BlockSize:]
	}
}

// XORKeyStream
func (s *salsa20Impl) XORKeyStream(dst, src []byte) {
	var key []byte

	dst = dst[:len(src)]

	// first block, if partial / buffer left
	if s.blockOffset > 0 {
		rem := Salsa_BlockSize - s.blockOffset
		key = s.block[s.blockOffset:]

		// not the rest of the block left
		if rem > len(src) {
			for i, v := range src {
				dst[i] = v ^ key[i]
			}
			s.blockOffset += len(src)
			return
		}

		// at least the rest of the block left
		for i, v := range key {
			dst[i] = src[i] ^ v
		}

		dst = dst[rem:]
		src = src[rem:]
	}

	// full blocks
	for len(dst) >= Salsa_BlockSize {
		s.nextState()

		for i, v := range s.block {
			dst[i] = src[i] ^ v
		}

		dst = dst[Salsa_BlockSize:]
		src = src[Salsa_BlockSize:]
	}

	// partial block
	if rem := len(dst); rem > 0 {
		s.nextState()

		for i, v := range src {
			dst[i] = v ^ s.block[i]
		}

		s.blockOffset = rem
	}
}

func (s *salsa20Impl) Seek(counter uint64) (st godium.Stream) {
	st = s

	binary.LittleEndian.PutUint64(s.counter[8:], counter)

	return
}

func (s *salsa20Impl) KeyBytes() int { return Salsa20_KeyBytes }
func (s *salsa20Impl) NonceBytes() int {
	if s.isXSalsa {
		return 24
	} else {
		return 8
	}
}
