// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package secretstream // import "go.artemisc.eu/godium/secretstream"

import (
	"go.artemisc.eu/godium"
)

const (
	ABytes      = XChacha20Poly1305_ABytes
	HeaderBytes = XChacha20Poly1305_HeaderBytes
	KeyBytes    = XChacha20Poly1305_KeyBytes
	TAG_MESSAGE = XChacha20Poly1305_TAG_MESSAGE
	TAG_PUSH    = XChacha20Poly1305_TAG_PUSH
	TAG_REKEY   = XChacha20Poly1305_TAG_REKEY
	TAG_FINAL   = XChacha20Poly1305_TAG_FINAL
)

// New
func New() (s godium.SecretStream) {
	s = NewXChacha20Poly1305()
	return
}
