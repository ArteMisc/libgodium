// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package godium

import (
	"crypto/cipher"
	"io"
	"hash"
)

// Wipe will override the contents of the buffer p with 0's.
func Wipe(p []byte) {
	for i := range p {
		p[i] = 0x00
	}
}

// Wiper defines an interface that types implement to indicate they can wipe
// their internal state.
type Wiper interface {
	Wipe()
}

// AEAD
type AEAD interface {
	cipher.AEAD
	Wiper

	// TODO provide a Detached interface
	//
	//SealDetached(dstCipher, dstTag, nonce, plaintext, ad []byte) (cipher, tag []byte)
	//
	//OpenDetached(dst, nonce, cipher, tag, ad []byte) (plain []byte, err error)

	KeyBytes() (c int)

	NSecBytes() (c int)

	NPubBytes() (c int)

	ABytes() (c int)
}

// Auth
type Auth interface {
	hash.Hash

	Wiper

	// Verify will check if the resulting Sum() of the Auth equals the provided
	// authentication tag.
	Verify(tag []byte) (matches bool)
}

// GenericHash
type GenericHash interface {
	hash.Hash
	Wiper
}

// Hash
type Hash interface {
	hash.Hash
}

// OneTimeAuth
type OneTimeAuth interface {
	Auth

	Init(key []byte)
}

// Random provides
type Random interface {
	UInt32() uint32
	UniformUInt32(upper uint32) uint32

	UInt64() uint64
	UniformUInt64(upper uint64) uint64

	// Buf will fill the buffer p with random bytes.
	Buf(p []byte) (err error)

	// KeyGen is a simplified call to Buf which allocates the byte slice to fit
	// the provided key size.
	KeyGen(size int) (key []byte, err error)

	// Implements the io.Reader interface, functions like Buf(p)
	io.Reader
}
