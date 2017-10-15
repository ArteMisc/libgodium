// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package kdf

import (
	"encoding/binary"

	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/generichash"
)

const (
	Blake2b_BytesMin     = 16
	Blake2b_BytesMax     = 64
	Blake2b_ContextBytes = 8
	Blake2b_KeyBytes     = 32
)

// Blake2b implements the godium.Kdf interface for key derivations based on
// keyed Blake2b.
type Blake2b struct {
	Key     []byte
	Context [8]byte
}

// NewBlake2b
func NewBlake2b(key, ctx []byte) (b *Blake2b) {
	b = new(Blake2b)
	b.Key = core.Copy(key, Blake2b_KeyBytes)
	copy(b.Context[:], ctx)
	return
}

// Wipe
func (k *Blake2b) Wipe() {
	godium.Wipe(k.Key)
	godium.Wipe(k.Context[:])
}

// Derive
func (k *Blake2b) Derive(dst []byte, length, id uint64) (subKey []byte) {
	var context [generichash.Blake2b_PersonalBytes]byte
	var salt [generichash.Blake2b_SaltBytes]byte

	subKey = core.AllocDst(dst, length)
	copy(context[:8], k.Context[:])
	for i := range context[8:] {
		context[i] = 0x00
	}

	binary.LittleEndian.PutUint64(salt[:8], id)
	for i := range salt[8:] {
		context[i] = 0x00
	}

	h := generichash.NewBlake2bSaltPersonal(uint32(length), k.Key, context[:], salt[:])
	h.Sum(subKey[:0])

	return
}

func (k *Blake2b) BytesMin() (c int)     { return Blake2b_BytesMin }
func (k *Blake2b) BytesMax() (c int)     { return Blake2b_BytesMax }
func (k *Blake2b) ContextBytes() (c int) { return Blake2b_ContextBytes }
func (k *Blake2b) KeyBytes() (c int)     { return Blake2b_KeyBytes }
