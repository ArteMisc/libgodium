// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package kx // import "go.artemisc.eu/godium/kx"

import (
	"go.artemisc.eu/godium"
)

const (
	Primitive       = "x25519blake2b"
	PublicKeyBytes  = X25519Blake2b_PublicKeyBytes
	SecretKeyBytes  = X25519Blake2b_SecretKeyBytes
	SeedBytes       = X25519Blake2b_SeedBytes
	SessionKeyBytes = X25519Blake2b_SessionKeyBytes
)

// New
func New(public godium.PublicKey, private godium.PrivateKey) (kx godium.Kx) {
	kx = NewX25519Blake2b(public, private)
	return
}
