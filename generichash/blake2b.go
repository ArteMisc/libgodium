// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package generichash

import (
	"hash"

	"github.com/minio/blake2b-simd"
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
)

const (
	Blake2b_BytesMin      = 16
	Blake2b_BytesMax      = 64
	Blake2b_Bytes         = 32
	Blake2b_KeyBytesMin   = 16
	Blake2b_KeyBytesMax   = 64
	Blake2b_KeyBytes      = 32
	Blake2b_SaltBytes     = 16
	Blake2b_PersonalBytes = 16

	size256 = 32
	size512 = 64
)

// Blake2b
type Blake2b struct {
	hash.Hash
}

// Blake2bSum256
func Blake2bSum256(data []byte) (sum [32]byte) {
	b := NewBlake2b256(nil)
	b.Write(data)
	b.Sum(sum[:0])
	return
}

// Blake2bSum512
func Blake2bSum512(data []byte) (sum [64]byte) {
	b := NewBlake2b512(nil)
	b.Write(data)
	b.Sum(sum[:0])
	return
}

// NewBlake2b256
func NewBlake2b256(key []byte) (gh godium.GenericHash) {
	var h hash.Hash
	if len(key) == 0 {
		h = blake2b.New256()
	} else {
		h = blake2b.NewMAC(size256, key)
	}
	gh = &Blake2b{
		Hash: h,
	}
	return
}

// NewBlake2b512
func NewBlake2b512(key []byte) (gh godium.GenericHash) {
	var h hash.Hash
	if len(key) == 0 {
		h = blake2b.New512()
	} else {
		h = blake2b.NewMAC(size512, key)
	}
	gh = &Blake2b{
		Hash: h,
	}
	return
}

// NewBlake2bXOF
func NewBlake2b(size uint32, key []byte) (gh godium.GenericHash) {
	h := blake2b.NewMAC(uint8(size), key)
	gh = &Blake2b{
		Hash: h,
	}
	return
}

// NewBlake2bSaltPersonal
func NewBlake2bSaltPersonal(size uint32, key, personal, salt []byte) (b *Blake2b) {
	c := new(blake2b.Config)
	c.Size = uint8(size)
	c.Key = core.Copy(key, uint64(len(key)))
	if personal != nil {

		c.Person = core.Copy(personal, Blake2b_PersonalBytes)
	}
	if salt != nil {
		c.Salt = core.Copy(salt, Blake2b_SaltBytes)
	}
	h, _ := blake2b.New(&blake2b.Config{})

	b = &Blake2b{
		Hash: h,
	}
	return
}

// Wipe
func (b *Blake2b) Wipe() {
	b.Hash.Reset()
}

func (b *Blake2b) BytesMin() int      { return Blake2b_BytesMin }
func (b *Blake2b) BytesMax() int      { return Blake2b_BytesMax }
func (b *Blake2b) Bytes() int         { return Blake2b_Bytes }
func (b *Blake2b) KeyBytesMin() int   { return Blake2b_KeyBytesMin }
func (b *Blake2b) KeyBytesMax() int   { return Blake2b_KeyBytesMax }
func (b *Blake2b) KeyBytes() int      { return Blake2b_KeyBytes }
func (b *Blake2b) PersonalBytes() int { return Blake2b_PersonalBytes }
func (b *Blake2b) SaltBytes() int     { return Blake2b_SaltBytes }
