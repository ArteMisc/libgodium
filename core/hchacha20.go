// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"unsafe"

	"git.schwanenlied.me/yawning/chacha20.git"
	"go.artemisc.eu/godium/internal"
)

const (
	HChacha20_OutputBytes = 32
	HChacha20_InputBytes  = 16
	HChacha20_KeyBytes    = 32
	HChacha20_ConstBytes  = 16
)

// HChacha20 implements the chacha20 hash function
func HChacha20(dst, nonce, key, sigma []byte) (out []byte) {
	if len(sigma) == 0 {
		// todo set to default sigma
	} else {
		// for now, not supported
		panic("HChacha20: using own sigma not yet supported")
	}

	if len(nonce) < HChacha20_InputBytes {
		panic("invalid nonce size")
	}

	out = internal.AllocDst(dst, HChacha20_OutputBytes)

	chacha20.HChaCha(key,
		(*[HChacha20_InputBytes]byte)(unsafe.Pointer(&nonce[0])),
		(*[HChacha20_OutputBytes]byte)(unsafe.Pointer(&out[0])))

	return
}
