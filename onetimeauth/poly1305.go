// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*

 */
package onetimeauth // import "go.artemisc.eu/godium/onetimeauth"

import (
	"github.com/Yawning/poly1305"
	"go.artemisc.eu/godium"
	"crypto/hmac"
)

const (
	Poly1305_Bytes    = 16
	Poly1305_KeyBytes = 32

	Primitive = "poly1305"
	Bytes     = Poly1305_Bytes
	KeyBytes  = Poly1305_KeyBytes
)

type poly1305Impl struct {
	*poly1305.Poly1305
	key []byte
}

// New
func New(key []byte) (a godium.OneTimeAuth) {
	a = NewPoly1305(key)
	return
}

// NewPoly1305
func NewPoly1305(key []byte) (a godium.OneTimeAuth) {
	h, _ := poly1305.New(key)
	a = &poly1305Impl{
		Poly1305: h,
		key: key,
	}
	return
}

// Wipe
func (p *poly1305Impl) Wipe() {
	godium.Wipe(p.key)
	p.Poly1305.Clear()
}

// Verify
func (p *poly1305Impl) Verify(tag []byte) (valid bool) {
	valid = hmac.Equal(p.Sum(nil), tag)
	return
}