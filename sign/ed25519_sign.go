// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package sign

import (
	"unsafe"

	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/hash"
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
	godium.PrivateKey
	godium.PublicKey
	Multipart godium.Hash
}

// NewEd25519
func NewEd25519(key godium.PrivateKey) (s godium.Sign) {
	key = core.Copy(key, Ed25519_SecretKeyBytes)
	s = &Ed25519Sign{
		PrivateKey: key,
		PublicKey:  godium.PublicKey(key[Ed25519_SeedBytes:Ed25519_SecretKeyBytes]),
	}
	return
}

func (s *Ed25519Sign) Wipe() {
	godium.Wipe(s.PrivateKey)
}

func (s *Ed25519Sign) Write(p []byte) (n int, err error) {
	if s.Multipart == nil {
		s.Multipart = hash.NewSha512()
	}
	n, err = s.Multipart.Write(p)
	return
}

func (s *Ed25519Sign) Sign(dst, unsigned []byte) (signed []byte) {
	mlen := uint64(len(unsigned))
	signed = core.AllocDst(dst, mlen+Ed25519_Bytes)

	if len(unsigned) == 0 {
		signed = s.SignDetached(dst[:0], unsigned)
		return
	}

	if uintptr(unsafe.Pointer(&dst[0])) != uintptr(unsafe.Pointer(&unsigned[Ed25519_Bytes])) {
		copy(dst, unsigned)
	}

	s.SignDetached(signed[:0], signed[Ed25519_Bytes:])
	return
}

// SignDetached
func (s *Ed25519Sign) SignDetached(dst, unsigned []byte) (signature []byte) {
	signature = core.AllocDst(dst, Ed25519_Bytes)
	edSign := edwards25519.Sign(signature[:0], unsigned, s.PrivateKey, false)
	copy(signature, edSign)
	return
}

// Final
func (s *Ed25519Sign) Final(dst []byte) (signature []byte) {
	if s.Multipart == nil {
		return // TODO fail/panic?
	}
	ph := make([]byte, 0, hash.Sha512_Bytes)
	ph = s.Multipart.Sum(ph)
	signature = edwards25519.Sign(dst, ph, s.PrivateKey, true)
	return
}

func (s *Ed25519Sign) PublicKeyBytes() (c int) { return Ed25519_PublicKeyBytes }
func (s *Ed25519Sign) SecretKeyBytes() (c int) { return Ed25519_SecretKeyBytes }
func (s *Ed25519Sign) Bytes() (c int)          { return Ed25519_Bytes }
func (s *Ed25519Sign) SeedBytes() (c int)      { return Ed25519_SeedBytes }
