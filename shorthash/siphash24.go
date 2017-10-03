// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package shorthash

import (
	"encoding/binary"
	"hash"

	"github.com/dchest/siphash"
	"go.artemisc.eu/godium"
)

const (
	Siphash24_Bytes    = 8
	Siphash24_KeyBytes = 16

	Siphash24x_Bytes    = 16
	Siphash24x_KeyBytes = 16

	Primitive = "siphash24"
	Bytes     = Siphash24_Bytes
	KeyBytes  = Siphash24_KeyBytes
)

type siphashImpl struct {
	hash.Hash
}

func ShortHash64(key, data []byte) (sum uint64) {
	sum = Siphash24(key, data)
	return
}

func ShortHash128(key, data []byte) (s1, s2 uint64) {
	s1, s2 = Siphash24x(key, data)
	return
}

func Siphash24(key, data []byte) (sum uint64) {
	sum = siphash.Hash(
		binary.LittleEndian.Uint64(key[:8]),
		binary.LittleEndian.Uint64(key[8:]),
		data)
	return
}

func Siphash24x(key, data []byte) (s1, s2 uint64) {
	s1, s2 = siphash.Hash128(
		binary.LittleEndian.Uint64(key[:8]),
		binary.LittleEndian.Uint64(key[8:]),
		data)
	return
}

func New(key []byte) (h godium.ShortHash64) {
	h = NewSiphash24(key)
	return
}

func NewSiphash24(key []byte) (h godium.ShortHash64) {
	h = &siphashImpl{
		Hash: siphash.New(key),
	}
	return
}

func NewSiphash24x(key []byte) (h godium.ShortHash128) {
	h = &siphashImpl{
		Hash: siphash.New128(key),
	}
	return
}

func (h *siphashImpl) Sum64() (s uint64) {
	s = h.Hash.(hash.Hash64).Sum64()
	return
}

func (h *siphashImpl) Sum128() (s1, s2 uint64) {
	sum := h.Hash.Sum(nil)
	s1 = binary.LittleEndian.Uint64(sum[:8])
	s1 = binary.LittleEndian.Uint64(sum[8:])
	return
}

func (h *siphashImpl) Bytes() int    { return h.Hash.Size() }
func (h *siphashImpl) KeyBytes() int { return Siphash24_KeyBytes }
