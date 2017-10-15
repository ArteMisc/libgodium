// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package aead

import (
	"crypto/aes"
	"crypto/cipher"

	"go.artemisc.eu/godium"
)

const (
	Aes256Gcm_KeyBytes  = 32
	Aes256Gcm_NSecBytes = 0
	Aes256Gcm_NPubBytes = 12
	Aes256Gcm_ABytes    = 16
)

type aes256gcm struct {
	cipher.AEAD
	key []byte
}

// NewAes256Gcm
func NewAes256Gcm(key []byte) (aesImpl godium.AEAD) {
	block, _ := aes.NewCipher(key)
	impl, _ := cipher.NewGCMWithNonceSize(block, Aes256Gcm_NPubBytes)
	aesImpl = &aes256gcm{
		AEAD: impl,
		key:  key,
	}
	return
}

// SealDetached
func (a *aes256gcm) SealDetached(dst, dstMac, nonce, plain, ad []byte) (cipher, mac []byte) {
	panic("aes256gcm: SealDetached not supported")
}

// OpenDetached
func (a *aes256gcm) OpenDetached(dst, nonce, cipher, mac, ad []byte) (plain []byte, err error) {
	panic("aes256gcm: SealDetached not supported")
}

// Wipe
func (a *aes256gcm) Wipe() {
	godium.Wipe(a.key)
}

func (a *aes256gcm) Overhead() int  { return Aes256Gcm_ABytes }
func (a *aes256gcm) NonceSize() int { return Aes256Gcm_NPubBytes }
func (a *aes256gcm) KeyBytes() int  { return Aes256Gcm_KeyBytes }
func (a *aes256gcm) NSecBytes() int { return Aes256Gcm_NSecBytes }
func (a *aes256gcm) NPubBytes() int { return Aes256Gcm_NPubBytes }
func (a *aes256gcm) ABytes() int    { return Aes256Gcm_ABytes }
