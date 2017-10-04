// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Based on https://github.com/golang/crypto/blob/master/ed25519/ed25519.go
package edwards25519

import (
	"bytes"
	"crypto/sha512"
	"strconv"

	"go.artemisc.eu/godium/core"
)

const (
	publicKeySize  = 32
	privateKeySize = 64
	signatureSize  = 64
)

var dom2prefix [32 + 2]byte = [...]byte{
	'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ',
	'n', 'o', ' ',
	'E', 'd', '2', '5', '5', '1', '9', ' ',
	'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 1, 0,
}

// Sign will sign a message using EdDSA (ed25519). If the flag ph is set to true
// it will assume that message holds a pre-hashed value, thus use Ed25519ph
// instead.
//
// It will panic if len(privateKey) is not privateKeySize
func Sign(dst, message, privateKey []byte, ph bool) (signature []byte) {
	if l := len(privateKey); l != privateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()
	h.Write(privateKey[:32])

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h.Reset()
	if ph {
		h.Write(dom2prefix[:])
	}
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	ScReduce(&messageDigestReduced, &messageDigest)
	var R ExtendedGroupElement
	GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(privateKey[32:])
	h.Write(message)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature = core.AllocDst(dst, signatureSize)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.
func Verify(message, sig, publicKey []byte, ph bool) bool {
	if l := len(publicKey); l != publicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != signatureSize || sig[63]&224 != 0 {
		return false
	}

	var A ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	FeNeg(&A.X, &A.X)
	FeNeg(&A.T, &A.T)

	h := sha512.New()
	if ph {
		h.Write(dom2prefix[:])
	}
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	ScReduce(&hReduced, &digest)

	var R ProjectiveGroupElement
	var b [32]byte
	copy(b[:], sig[32:])
	GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return bytes.Equal(sig[:32], checkR[:])
}
