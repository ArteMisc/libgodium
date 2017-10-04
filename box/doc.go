// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package box // import "go.artemisc.eu/godium/box"

import (
	"go.artemisc.eu/godium"
)

const (
	Primitive      = "curve25519xsalsa20poly1305"
	PublicKeyBytes = Curve25519XSalsa20Poly1305_PublicKeyBytes
	SecretKeyBytes = Curve25519XSalsa20Poly1305_SecretKeyBytes
	MacBytes       = Curve25519XSalsa20Poly1305_MacBytes
	NonceBytes     = Curve25519XSalsa20Poly1305_NonceBytes
	SeedBytes      = Curve25519XSalsa20Poly1305_SeedBytes
	BeforeNmBytes  = Curve25519XSalsa20Poly1305_BeforeNmBytes
)

// New
func New(private, public []byte) (box godium.Box) {
	box = NewCurve25519XSalsa20Poly1305(private, public)
	return
}
