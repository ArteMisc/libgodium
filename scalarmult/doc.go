// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package scalarmult // import "go.artemisc.eu/godium/scalarmult"

const (
	Primitive   = "curve25519"
	Bytes       = Curve25519_Bytes
	ScalarBytes = Curve25519_ScalarBytes
)

// ScalarMult
func ScalarMult(dst, in, base []byte) (out []byte, err error) {
	out, err = Curve25519(dst, in, base)
	return
}

// ScalarMultBase
func ScalarMultBase(dst, in []byte) (out []byte) {
	out = Curve25519Base(dst, in)
	return
}
