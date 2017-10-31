// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package random

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/internal"
)

//
type impl struct {
	io.Reader
}

//
func New() (rnd godium.Random) {
	rnd = NewFrom(rand.Reader)
	return
}

//
func NewFrom(r io.Reader) (rnd godium.Random) {
	rnd = impl{
		Reader: r,
	}
	return
}

// KeyGen
func (r impl) KeyGen(size int) (key []byte, err error) {
	key = make([]byte, size)
	err = r.Buf(key)
	return
}

// Buf
func (r impl) Buf(p []byte) (err error) {
	_, err = r.Read(p)
	return
}

// UInt32
func (r impl) UInt32() (v uint32) {
	_ = binary.Read(r.Reader, internal.NativeEndian, &v)
	return
}

// UniformUInt32
func (r impl) UniformUInt32(upper uint32) (v uint32) {
	if upper < 2 {
		return
	}

	min := (1 + ^upper) % upper /* = 2**32 mod upper_bound */

	for {
		v = r.UInt32()
		if v >= min {
			break
		}
	}

	/* r is now clamped to a set whose size mod upper_bound == 0
	 * the worst case (2**31+1) requires ~ 2 attempts */

	v = v % upper
	return
}

// UInt64
func (r impl) UInt64() (v uint64) {
	binary.Read(r.Reader, internal.NativeEndian, &v)
	return
}

// UniformUInt64
func (r impl) UniformUInt64(upper uint64) (v uint64) {
	if upper < 2 {
		return
	}

	min := (1 + ^upper) % upper /* = 2**64 mod upper_bound */

	for {
		v = r.UInt64()
		if v >= min {
			break
		}
	}

	/* r is now clamped to a set whose size mod upper_bound == 0
	 * the worst case (2**63+1) requires ~ 2 attempts */

	v = v % upper
	return
}
