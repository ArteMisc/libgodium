// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package stream // import "go.artemisc.eu/godium/stream"

import (
	"go.artemisc.eu/godium"
)

const (
	Primitive  = "xsalsa"
	KeyBytes   = XSalsa20_KeyBytes
	NonceBytes = XSalsa20_NonceBytes
)

// New
func New(key, nonce []byte) (s godium.Stream){
	s = NewXSalsa20(key, nonce)
	return
}
