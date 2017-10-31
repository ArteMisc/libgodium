// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pwhash

import (
	"math"

	"go.artemisc.eu/godium/internal"
)

const (
	Argon2i_Alg                 = 1
	Argon2i_BytesMin            = 16
	Argon2i_BytesMax            = math.MaxUint32
	Argon2i_PasswdMin           = 0
	Argon2i_PasswdMax           = 4294967295
	Argon2i_MemLimitMin         = 8192
	Argon2i_MemLimitMax         = 4398046510080
	Argon2i_MemLimitInteractive = 33554432
	Argon2i_MemLimitModerate    = 134217728
	Argon2i_MemLimitSensitive   = 536870912
	Argon2i_OpsLimitMin         = 3
	Argon2i_OpsLimitMax         = 4294967295
	Argon2i_OpsLimitInteractive = 4
	Argon2i_OpsLimitModerate    = 6
	Argon2i_OpsLimitSensitive   = 8
	Argon2i_SaltBytes           = 16
	Argon2i_StrBytes            = 128
	Argon2i_StrPrefix           = "$argon2i$"
)

// Argon2i
type Argon2i struct {
	pw []byte
}

// NewArgon2i
func NewArgon2i(pw []byte) (a *Argon2i) {
	a = &Argon2i{
		pw: internal.Copy(pw, uint64(len(pw))),
	}
	return
}

// Hash
func (pw *Argon2i) Hash(dst, salt []byte, out, opslimit, memlimit uint64) (h []byte) {
	return
}

// Str
func (pw *Argon2i) Str(dst []byte, opslimit, memlimit uint64) (h []byte) {
	return
}

// StrVerify
func (pw *Argon2i) StrVerify(h []byte) (valid bool) {
	return
}
