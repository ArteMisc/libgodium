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

	// ErrInvalidPoint is returned when a point on an elliptic curve is
	// considered illegal, unsafe, or incorrectly formatted.
	ErrInvalidPoint = errors.New("elliptic curve point not valid, rejected, or considered unsafe")

	// ErrCipherTooShort is returned when a ciphertext is shorter than a minimal
	// amount of bytes, for example when an authenticated ciphertext is not long
	// enough to at least contain the full authentication tag.
	ErrCipherTooShort = errors.New("cipher shorter than minimal size")

	// ErrBufferTooShort is returned when a buffer provided to a method is
	// shorter than a minimal amount of expected bytes, for example a header
	// that should at least contain a certain amount of bytes to hold a full
	// piece of data for an algorithm.
	ErrBufferTooShort = errors.New("buffer shorter than expected size")
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
	Hash
	Wiper

	// Verify will check if the resulting Sum() of the Auth equals the provided
	// authentication tag.
	Verify(tag []byte) (matches bool)

	KeyBytes() (c int)
}

// Box
type Box interface {
	Wiper

	SealDetached(dst, dstMac, nonce, plain []byte, remote PublicKey) (cipher, mac []byte, err error)

	Seal(dst, nonce, plain []byte, remote PublicKey) (cipher []byte, err error)

	OpenDetached(dst, nonce, cipher, mac []byte, remote PublicKey) (plain []byte, err error)

	Open(dst, nonce, cipher []byte, remote PublicKey) (plain []byte, err error)

	BeforeNM(remote PublicKey) (sb SecretBox, err error)

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

// Kdf
type Kdf interface {
	Wiper

	// Derive
	Derive(dst []byte, subKeyLength, subKeyId uint64) (subKey []byte)

	BytesMin() (c int)
	BytesMax() (c int)
	ContextBytes() (c int)
	KeyBytes() (c int)
}

// Kx
type Kx interface {
	Wiper

	// ServerSessionKeys
	ServerSessionKeys(dstRx, dstTx []byte, remote PublicKey) (rx, tx Key, err error)

	// ServerSessionKeys
	ClientSessionKeys(dstRx, dstTx []byte, remote PublicKey) (rx, tx Key, err error)

	PublicKeyBytes() (c int)
	SecretKeyBytes() (c int)
	SeedBytes() (c int)
	SessionKeyBytes() (c int)
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

type SecretStream interface {
	InitPush(dst []byte, key Key) (header []byte)
	InitPull(header []byte, key Key) (err error)
	Push(dst, plain, ad []byte, tag byte) (cipher []byte)
	Pull(dst, cipher, ad []byte) (plain []byte, tag byte, err error)
	ReKey()

	ABytes() (c int)
	HeaderBytes() (c int)
	KeyBytes() (c int)
	TAG_MESSAGE() (c byte)
	TAG_PUSH() (c byte)
	TAG_REKEY() (c byte)
	TAG_FINAL() (c byte)
}

// ShortHash
type ShortHash interface {
	Hash

	KeyBytes() (c int)
}

// ShortHash64Func
type ShortHash64Func func(key, data []byte) (sum uint64)

// ShortHash128Func
type ShortHash128Func func(key, data []byte) (sum1, sum2 uint64)

// ShortHash64
type ShortHash64 interface {
	ShortHash
	Sum64() (sum uint64)
}

// ShortHash128
type ShortHash128 interface {
	ShortHash
	Sum128() (s1, s2 uint64)
}

// Sign
type Sign interface {
	Wiper

	// Detached signs the message data in unsigned, and returns a message with
	// the signature
	Sign(dst, unsigned []byte) (signed []byte)

	// SignDetached creates a signature
	SignDetached(dst, unsigned []byte) (signature []byte)

	// io.Writer provides the Write method to the Signature interface. When
	// Write is used, the Signature implementation moves to Multipart mode,
	// which pre-hashes the message before signing.
	//
	// Note that this may produce a different signature then when full-message
	// signatures are used, as the pre-hashing generated a different value for
	// the signature key to sign.
	io.Writer

	// Final is the SignDetached method's equivalent for Multipart messages.
	// This operation will fail if Write has not been called before.
	Final(dst []byte) (signature []byte)

	PublicKeyBytes() (c int)
	SecretKeyBytes() (c int)
	Bytes() (c int)
	SeedBytes() (c int)
}

// SignVerifier
type SignVerifier interface {
	// Open will verify the signature, and return the message data without the
	// signature.
	Open(dst, signed []byte) (unsigned []byte, valid bool)

	// VerifyDetached is the detached equivalent of Open, which simply verifies
	// the signature.
	VerifyDetached(signature, message []byte) (valid bool)

	// io.Writer provides the Write method to the Signature interface. When
	// Write is used, the Signature implementation moves to Multipart mode,
	// which pre-hashes the message before signing.
	//
	// Note that this may produce a different signature then when full-message
	// signatures are used, as the pre-hashing generated a different value for
	// the signature key to sign.
	io.Writer

	// FinalVerify is the Verify method's equivalent for Multipart messages.
	// This operation will fail if Write has not been called before.
	FinalVerify(signature []byte) (valid bool)

	PublicKeyBytes() (c int)
	SecretKeyBytes() (c int)
	Bytes() (c int)
	SeedBytes() (c int)
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

	// ReKey will re-initialize the stream with the given key/nonce combination.
	ReKey(key, nonce []byte)

	KeyBytes() (c int)
	NonceBytes() (c int)
	BlockBytes() (c int)
}

// Codec implements a constant-time encoding algorithm to convert between binary
// data a printable text representation.
type Codec interface {
	// Encode appends the encoded value of bin to dst.
	Encode(dst, bin []byte) (txt []byte)

	// Decode appends the decoded value of txt to dst.
	Decode(dst, txt []byte) (bin []byte)

	// EncodedLength calculates what the length of the encoded value would be
	// for this codec.
	EncodedLength(decoded int) (encoded int)

	// DecodedLength calculates what the length of the decoded value would be
	// for this codec.
	DecodedLength(encoded int) (decoded int)
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

// Multipart is the generic interface used to describe a primitive that can
// update its state incrementally.
type Multipart interface {
	// Writer implements the Write method, which can be used to update the state
	// of the Multipart
	io.Writer

	Update(p []byte) Multipart

	Final(dst []byte) (out []byte)

	FinalVerify(expect []byte) (valid bool)
}
