// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package godium

import (
	"crypto/cipher"
	"errors"
	"hash"
	"io"
)

var (
	// ErrForgedOrCorrupted is returned by decryption method that perform
	// message authentication whenever the authentication check fails. When such
	// a check fails, it indicates that the message is either forged, corrupted,
	// or incorrectly encrypted. These could be indicators of protocol or
	// implementation failures, but also be a sign of an active
	// man-in-the-middle attack
	ErrForgedOrCorrupted = errors.New("authentication tag is invalid, message is forged or corrupted")
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

// Key
type Key []byte

// PrivateKey
type PrivateKey []byte

// PublicKey
type PublicKey []byte

// AEAD
type AEAD interface {
	cipher.AEAD
	Wiper

	SealDetached(dst, dstMac, nonce, plain, ad []byte) (cipher, mac []byte)

	OpenDetached(dst, nonce, cipher, mac, ad []byte) (plain []byte, err error)

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

	Bytes() (c int)
	KeyBytes() (c int)
}

// Box
type Box interface {
	Wiper

	Seal(dst, nonce, plain []byte, remote PublicKey) (cipher []byte)
	Open(dst, nonce, cipher []byte, remote PublicKey) (plain []byte, err error)

	// TODO Detached interface
	// SealDetached
	// OpenDetached

	BeforeNM() SecretBox

	PublicKeyBytes() (c int)
	SecretKeyBytes() (c int)
	MacBytes() (c int)
	NonceBytes() (c int)
	SeedBytes() (c int)
	BeforeNmBytes() (c int)
}

// GenericHash
type GenericHash interface {
	hash.Hash
	Wiper

	BytesMin() (c int)
	BytesMax() (c int)
	KeyBytesMin() (c int)
	KeyBytesMax() (c int)
	KeyBytes() (c int)
}

// Hash
type Hash interface {
	hash.Hash

	Bytes() (c int)
}

// OneTimeAuth
type OneTimeAuth interface {
	Auth

	// ReKey re-initializes the OneTimeAuth state with the new key. OneTimeAuth
	// instances should only be used once. To use it again, it needs to be
	// re-initialized with a new one-time key.
	ReKey(key []byte)
}

// SecretBox
type SecretBox interface {
	Wiper

	Seal(dst, nonce, plain []byte) (cipher []byte)

	SealDetached(dst, dstMac, nonce, plain []byte) (cipher, mac []byte)

	Open(dst, nonce, cipher []byte) (plain []byte, err error)

	OpenDetached(dst, nonce, cipher, mac []byte) (plain []byte, err error)

	KeyBytes() (c int)
	MacBytes() (c int)
	NonceBytes() (c int)
}

// Stream
type Stream interface {
	cipher.Stream
	Wiper

	// KeyStream generated len(dst) bytes of key from the stream
	KeyStream(dst []byte)

	// Seek sets the stream's internal counter. As this is usually followed
	// directly by a call to KeyStream or XORKeyStream, it returns a reference
	// to itself to enable chaining.
	//
	// example: stream.Seek(1).KeyStream(stream)
	Seek(counter uint64) Stream

	// ReKey will re-initialize the stream with the given key/nonce conbination.
	ReKey(key, nonce []byte)

	KeyBytes() (c int)
	NonceBytes() (c int)
	BlockBytes() (c int)
}

// Random provides an interface for CSPRNG functionality.
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
