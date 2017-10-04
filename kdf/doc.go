// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package kdf // import "go.artemisc.eu/godium/kdf"

import (
	"go.artemisc.eu/godium"
)

const (
	Primitive    = "blake2b"
	BytesMin     = Blake2b_BytesMin
	BytesMax     = Blake2b_BytesMax
	ContextBytes = Blake2b_ContextBytes
	KeyBytes     = Blake2b_KeyBytes
)

// New
func New(key, ctx []byte) (k godium.Kdf) {
	k = NewBlake2b(key, ctx)
	return
}
