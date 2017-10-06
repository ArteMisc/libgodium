// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package onetimeauth

import (
	"crypto/hmac"

	"github.com/Yawning/poly1305"
	"go.artemisc.eu/godium"
)

const (
	Poly1305_Bytes    = 16
	Poly1305_KeyBytes = 32
)

type Poly1305 struct {
	*poly1305.Poly1305
}

// NewPoly1305
func NewPoly1305(key godium.Key) (a *Poly1305) {
	h, _ := poly1305.New(key)
	a = &Poly1305{
		Poly1305: h,
	}
	return
}

// Wipe
func (p *Poly1305) Wipe() {
	p.Poly1305.Clear()
}

//
func (p *Poly1305) ReKey(key []byte) {
	p.Poly1305.Init(key)
}

// Verify
func (p *Poly1305) Verify(tag []byte) (valid bool) {
	valid = hmac.Equal(p.Sum(nil), tag)
	return
}

func (p *Poly1305) Bytes() int    { return Poly1305_Bytes }
func (p *Poly1305) KeyBytes() int { return Poly1305_KeyBytes }
