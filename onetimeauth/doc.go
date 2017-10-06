// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

Package OneTimeAuth implements primitives for secret key based one-time
authentication codes.

 */
package onetimeauth // import "go.artemisc.eu/godium/onetimeauth"

import (
	"go.artemisc.eu/godium"
)

const (
	Primitive = "poly1305"
	Bytes     = Poly1305_Bytes
	KeyBytes  = Poly1305_KeyBytes
)

// New
func New(key godium.Key) (a godium.OneTimeAuth) {
	a = NewPoly1305(key)
	return
}
