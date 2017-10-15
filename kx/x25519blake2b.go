// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package kx

import (
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/generichash"
	"go.artemisc.eu/godium/scalarmult"
)

const (
	X25519Blake2b_PublicKeyBytes  = 32
	X25519Blake2b_SecretKeyBytes  = 32
	X25519Blake2b_SeedBytes       = 32
	X25519Blake2b_SessionKeyBytes = 32
)

//
type X25519Blake2b struct {
	godium.PublicKey
	godium.PrivateKey
}

// NewX25519Blake2b
func NewX25519Blake2b(public godium.PublicKey, private godium.PrivateKey) (kx *X25519Blake2b) {
	kx = &X25519Blake2b{
		PublicKey:  core.Copy(public, X25519Blake2b_PublicKeyBytes),
		PrivateKey: core.Copy(private, X25519Blake2b_SecretKeyBytes),
	}
	return
}

// Wipe
func (kx *X25519Blake2b) Wipe() {
	godium.Wipe(kx.PrivateKey)
	godium.Wipe(kx.PublicKey)
}

// ServerSessionKeys
func (kx *X25519Blake2b) ServerSessionKeys(dstRx, dstTx []byte, remote godium.PublicKey) (rx, tx godium.Key, err error) {
	var q [scalarmult.Curve25519_Bytes]byte
	var keys [2 * X25519Blake2b_SessionKeyBytes]byte

	defer godium.Wipe(q[:])
	defer godium.Wipe(keys[:])

	rx = core.AllocDst(dstRx, X25519Blake2b_SessionKeyBytes)
	tx = core.AllocDst(dstTx, X25519Blake2b_SessionKeyBytes)

	_, err = scalarmult.Curve25519(q[:0], kx.PrivateKey, remote)
	if err != nil {
		return
	}

	h := generichash.NewBlake2b512(nil)
	h.Write(q[:])
	h.Write(kx.PublicKey)
	h.Write(remote)
	h.Sum(keys[:0])

	copy(rx[:], keys[:X25519Blake2b_SessionKeyBytes])
	copy(tx[:], keys[X25519Blake2b_SessionKeyBytes:])

	return
}

// ClientSessionKeys
func (kx *X25519Blake2b) ClientSessionKeys(dstRx, dstTx []byte, remote godium.PublicKey) (rx, tx godium.Key, err error) {
	var q [scalarmult.Curve25519_Bytes]byte
	var keys [2 * X25519Blake2b_SessionKeyBytes]byte

	defer godium.Wipe(q[:])
	defer godium.Wipe(keys[:])

	rx = core.AllocDst(dstRx, X25519Blake2b_SessionKeyBytes)
	tx = core.AllocDst(dstTx, X25519Blake2b_SessionKeyBytes)

	_, err = scalarmult.Curve25519(q[:0], kx.PrivateKey, remote)
	if err != nil {
		return
	}

	h := generichash.NewBlake2b512(nil)
	h.Write(q[:])
	h.Write(remote)
	h.Write(kx.PublicKey)
	h.Sum(keys[:0])

	copy(tx[:], keys[:X25519Blake2b_SessionKeyBytes])
	copy(rx[:], keys[X25519Blake2b_SessionKeyBytes:])

	return
}

func (kx *X25519Blake2b) PublicKeyBytes() int  { return X25519Blake2b_PublicKeyBytes }
func (kx *X25519Blake2b) SecretKeyBytes() int  { return X25519Blake2b_SecretKeyBytes }
func (kx *X25519Blake2b) SeedBytes() int       { return X25519Blake2b_SeedBytes }
func (kx *X25519Blake2b) SessionKeyBytes() int { return X25519Blake2b_SessionKeyBytes }
