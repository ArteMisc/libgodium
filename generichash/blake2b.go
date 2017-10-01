// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package generichash // import "go.artemisc.eu/godium/generichash"

import (
	"hash"

	"go.artemisc.eu/godium"
	"golang.org/x/crypto/blake2b"
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

	Primitive   = "blake2b"
	BytesMin    = Blake2b_BytesMin
	BytesMax    = Blake2b_BytesMax
	Bytes       = Blake2b_Bytes
	KeyBytesMin = Blake2b_KeyBytesMin
	KeyBytesMax = Blake2b_KeyBytesMax
	KeyBytes    = Blake2b_KeyBytes
)

type blake2bDigest struct {
	hash.Hash
	key []byte
}

type blake2bXof struct {
	blake2b.XOF
	outlen int
	key    []byte
}

// New
func New(outlen int, key []byte) (gh godium.GenericHash) {
	gh = NewBlake2b(outlen, key)
	return
}

// NewBlake2b
func NewBlake2b(outlen int, key []byte) (gh godium.GenericHash) {
	switch outlen {
	case 32:
		h, _ := blake2b.New256(key)
		gh = &blake2bDigest{
			Hash: h,
			key:  key,
		}
	case 48:
		h, _ := blake2b.New384(key)
		gh = &blake2bDigest{
			Hash: h,
			key:  key,
		}
	case 64:
		h, _ := blake2b.New512(key)
		gh = &blake2bDigest{
			Hash: h,
			key:  key,
		}
	default:
		xof, _ := blake2b.NewXOF(uint32(outlen), key)
		gh = &blake2bXof{
			XOF:    xof,
			outlen: outlen,
			key:    key,
		}
	}
	return
}

// Wipe
func (b *blake2bDigest) Wipe() {
	godium.Wipe(b.key)
}

func (b *blake2bDigest) BytesMin() int    { return Blake2b_BytesMin }
func (b *blake2bDigest) BytesMax() int    { return Blake2b_BytesMax }
func (b *blake2bDigest) Bytes() int       { return b.Size() }
func (b *blake2bDigest) KeyBytesMin() int { return Blake2b_KeyBytesMin }
func (b *blake2bDigest) KeyBytesMax() int { return Blake2b_KeyBytesMax }
func (b *blake2bDigest) KeyBytes() int    { return len(b.key) }

// Wipe
func (b *blake2bXof) Wipe() {
	godium.Wipe(b.key)
}

// Sum
func (b *blake2bXof) Sum(dst []byte) (sum []byte) {
	sum = append(dst, make([]byte, b.outlen)...)
	_, _ = b.XOF.Read(sum)
	return
}

func (b *blake2bXof) Size() int        { return b.outlen }
func (b *blake2bXof) BlockSize() int   { return 128 }
func (b *blake2bXof) BytesMin() int    { return Blake2b_BytesMin }
func (b *blake2bXof) BytesMax() int    { return Blake2b_BytesMax }
func (b *blake2bXof) Bytes() int       { return b.outlen }
func (b *blake2bXof) KeyBytesMin() int { return Blake2b_KeyBytesMin }
func (b *blake2bXof) KeyBytesMax() int { return Blake2b_KeyBytesMax }
func (b *blake2bXof) KeyBytes() int    { return len(b.key) }
