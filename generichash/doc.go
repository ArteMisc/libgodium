// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package generichash // import "go.artemisc.eu/godium/generichash"

import (
	"go.artemisc.eu/godium"
)

const (
	Primitive   = "blake2b"
	BytesMin    = Blake2b_BytesMin
	BytesMax    = Blake2b_BytesMax
	Bytes       = Blake2b_Bytes
	KeyBytesMin = Blake2b_KeyBytesMin
	KeyBytesMax = Blake2b_KeyBytesMax
	KeyBytes    = Blake2b_KeyBytes
)

// New
func New(size uint32, key []byte) (gh godium.GenericHash) {
	gh = NewBlake2b(size, key)
	return
}

// New
func New256(key []byte) (gh godium.GenericHash) {
	gh = NewBlake2b256(key)
	return
}

// New512
func New512(key []byte) (gh godium.GenericHash) {
	gh = NewBlake2b512(key)
	return
}

// Sum256
func Sum256(data []byte) (sum [32]byte) {
	b := New256(nil)
	b.Write(data)
	b.Sum(sum[:0])
	return
}

// Sum512
func Sum512(data []byte) (sum [64]byte) {
	b := New512(nil)
	b.Write(data)
	b.Sum(sum[:0])
	return
}
