// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package kx

import (
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/generichash"
	"go.artemisc.eu/godium/internal"
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
	public  godium.PublicKey
	private godium.PrivateKey
}

// NewX25519Blake2b
func NewX25519Blake2b(public godium.PublicKey, private godium.PrivateKey) (kx *X25519Blake2b) {
	kx = &X25519Blake2b{
		public:  internal.Copy(public, X25519Blake2b_PublicKeyBytes),
		private: internal.Copy(private, X25519Blake2b_SecretKeyBytes),
	}
	return
}

// KeyGenX25519Blake2b
func KeyGenX25519Blake2b(random godium.Random) (kx *X25519Blake2b, err error) {
	private, err := random.KeyGen(X25519Blake2b_SecretKeyBytes)
	if err != nil {
		return
	}

	public := make([]byte, scalarmult.Curve25519_ScalarBytes)
	scalarmult.Curve25519Base(public[:0], private)

	kx = &X25519Blake2b{
		public:  public,
		private: private,
	}
	return
}

// Wipe
func (kx *X25519Blake2b) Wipe() {
	godium.Wipe(kx.private)
	godium.Wipe(kx.public)
}

// ServerSessionKeys
func (kx *X25519Blake2b) ServerSessionKeys(dstRx, dstTx []byte, remote godium.PublicKey) (rx, tx godium.Key, err error) {
	var q [scalarmult.Curve25519_Bytes]byte
	var keys [2 * X25519Blake2b_SessionKeyBytes]byte

	defer godium.Wipe(q[:])
	defer godium.Wipe(keys[:])

	rx = internal.AllocDst(dstRx, X25519Blake2b_SessionKeyBytes)
	tx = internal.AllocDst(dstTx, X25519Blake2b_SessionKeyBytes)

	_, err = scalarmult.Curve25519(q[:0], kx.private, remote)
	if err != nil {
		return
	}

	h := generichash.NewBlake2b512(nil)
	h.Write(q[:])
	h.Write(kx.public)
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

	rx = internal.AllocDst(dstRx, X25519Blake2b_SessionKeyBytes)
	tx = internal.AllocDst(dstTx, X25519Blake2b_SessionKeyBytes)

	_, err = scalarmult.Curve25519(q[:0], kx.private, remote)
	if err != nil {
		return
	}

	h := generichash.NewBlake2b512(nil)
	h.Write(q[:])
	h.Write(remote)
	h.Write(kx.public)
	h.Sum(keys[:0])

	copy(tx[:], keys[:X25519Blake2b_SessionKeyBytes])
	copy(rx[:], keys[X25519Blake2b_SessionKeyBytes:])

	return
}

// PublicKey
func (kx *X25519Blake2b) PublicKey() godium.PublicKey {
	return internal.Copy(kx.public, X25519Blake2b_PublicKeyBytes)
}

func (kx *X25519Blake2b) PublicKeyBytes() int  { return X25519Blake2b_PublicKeyBytes }
func (kx *X25519Blake2b) SecretKeyBytes() int  { return X25519Blake2b_SecretKeyBytes }
func (kx *X25519Blake2b) SeedBytes() int       { return X25519Blake2b_SeedBytes }
func (kx *X25519Blake2b) SessionKeyBytes() int { return X25519Blake2b_SessionKeyBytes }
