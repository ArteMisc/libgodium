// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package pwhash // import "go.artemisc.eu/godium/pwhash"

import (
	"errors"

	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/random"
)

const (
	Primitive           = "argon2id"
	AlgArgon2i          = Argon2i_Alg
	AlgArgon2id         = Argon2id_Alg
	AlgDefault          = AlgArgon2id
	BytesMin            = Argon2i_BytesMin
	BytesMax            = Argon2i_BytesMax
	PasswdMin           = Argon2i_PasswdMin
	PasswdMax           = Argon2i_PasswdMax
	MemLimitMin         = Argon2i_MemLimitMin
	MemLimitMax         = Argon2i_MemLimitMax
	MemLimitInteractive = Argon2i_MemLimitInteractive
	MemLimitModerate    = Argon2i_MemLimitModerate
	MemLimitSensitive   = Argon2i_MemLimitSensitive
	OpsLimitMin         = Argon2i_OpsLimitMin
	OpsLimitMax         = Argon2i_OpsLimitMax
	OpsLimitInteractive = Argon2i_OpsLimitInteractive
	OpsLimitModerate    = Argon2i_OpsLimitModerate
	OpsLimitSensitive   = Argon2i_OpsLimitSensitive
	SaltBytes           = Argon2i_SaltBytes
	StrBytes            = Argon2i_StrBytes
	StrPrefix           = Argon2i_StrPrefix
)

//
var (
	ErrWrongAlg      = errors.New("wrong algorithm identifier found")
	ErrWrongPassword = errors.New("wrong password entered")
)

var (
	reader = random.New()
)

// New
func New(pw []byte) (ph godium.PwHash) {
	panic("Argon2i not yet implemented")
	return
}

// NeedsRehash
func NeedsRehash(h string, opslimit, memlimit uint64) (rehash bool) {
	// FIXME implement NeedsRehash
	return
}
