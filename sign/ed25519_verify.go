// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sign

import (
	"unsafe"

	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/hash"
	"go.artemisc.eu/godium/internal"
	"go.artemisc.eu/godium/internal/edwards25519"
)

type Ed25519SignVerifier struct {
	godium.PublicKey
	Multipart godium.Hash
}

func NewEd25519Verifier(key godium.PublicKey) (v godium.SignVerifier) {
	v = &Ed25519SignVerifier{
		PublicKey: key,
	}
	return
}

func (v *Ed25519SignVerifier) Write(p []byte) (n int, err error) {
	if v.Multipart == nil {
		v.Multipart = hash.NewSha512()
	}
	n, err = v.Multipart.Write(p)
	return
}

func (v *Ed25519SignVerifier) Open(dst, signed []byte) (unsigned []byte, valid bool) {
	valid = v.VerifyDetached(signed[:Ed25519_Bytes], signed[Ed25519_Bytes:])
	if !valid {
		return
	}

	mlen := uint64(len(signed)) - Ed25519_Bytes
	unsigned = internal.AllocDst(dst, mlen)

	if uintptr(unsafe.Pointer(&unsigned[0])) != uintptr(unsafe.Pointer(&signed[Ed25519_Bytes])) {
		copy(unsigned, signed[:])
	}
	return
}

func (v *Ed25519SignVerifier) VerifyDetached(signature, message []byte) (valid bool) {
	valid = edwards25519.Verify(message, signature, v.PublicKey, false)
	return
}

func (v *Ed25519SignVerifier) FinalVerify(signature []byte) (valid bool) {
	if v.Multipart == nil {
		// fail/misuse?
		return
	}

	ph := make([]byte, 0, hash.Sha512_Bytes)
	ph = v.Multipart.Sum(ph)

	valid = edwards25519.Verify(ph, signature, v.PublicKey, true)

	v.Multipart = nil
	return
}

func (v *Ed25519SignVerifier) PublicKeyBytes() (c int) { return Ed25519_PublicKeyBytes }
func (v *Ed25519SignVerifier) SecretKeyBytes() (c int) { return Ed25519_SecretKeyBytes }
func (v *Ed25519SignVerifier) Bytes() (c int)          { return Ed25519_Bytes }
func (v *Ed25519SignVerifier) SeedBytes() (c int)      { return Ed25519_SeedBytes }
