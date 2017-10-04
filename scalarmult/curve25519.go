// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package scalarmult

import (
	"unsafe"

	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"golang.org/x/crypto/curve25519"
)

const (
	Curve25519_Bytes       = 32
	Curve25519_ScalarBytes = 32
)

// Curve25519
func Curve25519(dst, in, base []byte) (out []byte, err error) {
	out = core.AllocDst(dst, Curve25519_ScalarBytes)
	curve25519.ScalarMult(
		(*[Bytes]byte)(unsafe.Pointer(&out[0])),
		(*[Bytes]byte)(unsafe.Pointer(&in[0])),
		(*[Bytes]byte)(unsafe.Pointer(&base[0])))

	// check for invalid resulting key
	d := byte(0)
	for _, v := range out {
		d |= v
	}
	if -(1 & ((d - 1) >> 8)) != 0 {
		out, err = nil, godium.ErrInvalidPoint
	}
	return
}

// Curve25519Base
func Curve25519Base(dst, in []byte) (out []byte) {
	out = core.AllocDst(dst, Curve25519_ScalarBytes)
	curve25519.ScalarBaseMult(
		(*[Bytes]byte)(unsafe.Pointer(&out[0])),
		(*[Bytes]byte)(unsafe.Pointer(&in[0])))
	return
}
