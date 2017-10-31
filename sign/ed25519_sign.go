// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sign

import (
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/hash"
	"go.artemisc.eu/godium/internal"
	"go.artemisc.eu/godium/sign/internal/edwards25519"
)

const (
	Ed25519_PublicKeyBytes = 32
	Ed25519_SecretKeyBytes = 64
	Ed25519_Bytes          = 64
	Ed25519_SeedBytes      = 32

	Ed25519ph_PublicKeyBytes = 32
	Ed25519ph_SecretKeyBytes = 64
	Ed25519ph_Bytes          = 64
	Ed25519ph_SeedBytes      = 32
)

type Ed25519Sign struct {
	private   godium.PrivateKey
	public    godium.PublicKey
	multipart godium.Hash
}

// NewEd25519
func NewEd25519(key godium.PrivateKey) (s godium.Sign) {
	key = internal.Copy(key, Ed25519_SecretKeyBytes)
	s = &Ed25519Sign{
		private: key,
		public:  godium.PublicKey(key[Ed25519_SeedBytes:Ed25519_SecretKeyBytes]),
	}
	return
}

// KeyPairEd25519
func KeyPairEd25519(random godium.Random) (s *Ed25519Sign, err error) {
	seed, err := random.KeyGen(Ed25519_SeedBytes)
	if err != nil {
		return
	}

	s = KeyPairSeedEd25519(seed)
	return
}

// KeyPairSeedEd25519
func KeyPairSeedEd25519(seed []byte) (s *Ed25519Sign) {
	seed = internal.Copy(seed, SeedBytes)
	defer godium.Wipe(seed)

	s = new(Ed25519Sign)
	s.private = make([]byte, Ed25519_SecretKeyBytes)
	s.public = godium.PublicKey(s.private[Ed25519_SeedBytes:])

	var hBytes [32]byte
	hash.SumSha512(hBytes[:0], s.private[:Ed25519_SeedBytes])
	hBytes[0] &= 248
	hBytes[31] &= 127
	hBytes[31] |= 64

	var A edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&A, &hBytes)
	A.ToBytes(&hBytes)
	copy(s.public[:], hBytes[:])

	return
}

// Wipe
func (s *Ed25519Sign) Wipe() {
	godium.Wipe(s.private)
}

// Write
func (s *Ed25519Sign) Write(p []byte) (n int, err error) {
	if s.multipart == nil {
		s.multipart = hash.NewSha512()
	}
	n, err = s.multipart.Write(p)
	return
}

func (s *Ed25519Sign) Sign(dst, unsigned []byte) (signed []byte) {
	mlen := uint64(len(unsigned))
	signed = internal.AllocDst(dst, mlen+Ed25519_Bytes)

	if len(unsigned) == 0 {
		signed = s.SignDetached(dst[:0], unsigned)
		return
	}

	if &dst[0] != &unsigned[Ed25519_Bytes] {
		copy(dst, unsigned)
	}

	s.SignDetached(signed[:0], signed[Ed25519_Bytes:])
	return
}

// SignDetached
func (s *Ed25519Sign) SignDetached(dst, unsigned []byte) (signature []byte) {
	signature = internal.AllocDst(dst, Ed25519_Bytes)
	edSign := edwards25519.Sign(signature[:0], unsigned, s.private, false)
	copy(signature, edSign)
	return
}

// Final
func (s *Ed25519Sign) Final(dst []byte) (signature []byte) {
	if s.multipart == nil {
		return // TODO fail/panic?
	}
	ph := make([]byte, 0, hash.Sha512_Bytes)
	ph = s.multipart.Sum(ph)
	signature = edwards25519.Sign(dst, ph, s.private, true)
	return
}

// PublicKey
func (s *Ed25519Sign) PublicKey() godium.PublicKey {
	return internal.Copy(s.public, Ed25519_PublicKeyBytes)
}

func (s *Ed25519Sign) PublicKeyBytes() (c int) { return Ed25519_PublicKeyBytes }
func (s *Ed25519Sign) SecretKeyBytes() (c int) { return Ed25519_SecretKeyBytes }
func (s *Ed25519Sign) Bytes() (c int)          { return Ed25519_Bytes }
func (s *Ed25519Sign) SeedBytes() (c int)      { return Ed25519_SeedBytes }
