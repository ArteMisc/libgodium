// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sign // import "go.artemisc.eu/godium/sign"

import (
	"go.artemisc.eu/godium"
)

const (
	Primitive          = "ed25519"
	PrimitiveMultipart = "ed25519ph"
	PublicKeyBytes     = Ed25519_PublicKeyBytes
	SecretKeyBytes     = Ed25519_SecretKeyBytes
	Bytes              = Ed25519_Bytes
	SeedBytes          = Ed25519_SeedBytes
)

// New
func New(key godium.PrivateKey) (s godium.Sign) {
	s = NewEd25519(key)
	return
}

// NewVerifier
func NewVerifier(key godium.PublicKey) (v godium.SignVerifier) {
	v = NewEd25519Verifier(key)
	return
}

// KeyPair
func KeyPair(random godium.Random) (s godium.Sign, err error) {
	s, err = KeyPairEd25519(random)
	return
}

// KeyPairSeed
func KeyPairSeed(seed []byte) (s godium.Sign) {
	s = KeyPairSeedEd25519(seed)
	return
}
