// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package scalarmult // import "go.artemisc.eu/godium/scalarmult"

import (
	"unsafe"

	"go.artemisc.eu/godium/core"
	"golang.org/x/crypto/curve25519"
)

const (
	Curve25519_Bytes       = 32
	Curve25519_ScalarBytes = 32

	Primitive   = "curve25519"
	Bytes       = Curve25519_Bytes
	ScalarBytes = Curve25519_ScalarBytes
)

// ScalarMult
func ScalarMult(dst, in, base []byte) (out []byte) {
	out = Curve25519(dst, in, base)
	return
}

// ScalarMultBase
func ScalarMultBase(dst, in []byte) (out []byte) {
	out = Curve2519Base(dst, in)
	return
}

// Curve25519
func Curve25519(dst, in, base []byte) (out []byte) {
	out = core.AllocDst(dst, Curve25519_ScalarBytes)
	curve25519.ScalarMult(
		(*[Bytes]byte)(unsafe.Pointer(&out[0])),
		(*[Bytes]byte)(unsafe.Pointer(&in[0])),
		(*[Bytes]byte)(unsafe.Pointer(&base[0])))
	return
}

// Curve2519Base
func Curve2519Base(dst, in []byte) (out []byte) {
	out = core.AllocDst(dst, Curve25519_ScalarBytes)
	curve25519.ScalarBaseMult(
		(*[Bytes]byte)(unsafe.Pointer(&out[0])),
		(*[Bytes]byte)(unsafe.Pointer(&in[0])))
	return
}
