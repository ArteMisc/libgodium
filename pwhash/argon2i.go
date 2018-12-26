// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pwhash

import (
	"math"

	"go.artemisc.eu/godium"
	"golang.org/x/crypto/argon2"
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

// Wipe implements godium.PwHash.
func (pw *Argon2i) Wipe() {
	godium.Wipe(pw.pw)
}

// pickParams
func (pw *Argon2i) pickParams(opslimit, memlimit uint64) (time, memory uint32) {
	panic("TODO")
	return
}

// Hash implements godium.PwHash.
func (pw *Argon2i) Hash(dst, salt []byte, out, opslimit, memlimit uint64) (h []byte) {
	h = pw.HashParallel(dst, salt, out, opslimit, memlimit, 1)
	return
}

// HashParallel functions like Hash, but accepts an additional parameter that
// specifies the level of parallelism for the generation of the hash.
func (pw *Argon2i) HashParallel(dst, salt []byte, out, opslimit, memlimit uint64, threads uint8) (h []byte) {
	if threads < 1 {
		panic("argon2i: at least 1 thread required")
	}

	time, memory := pw.pickParams(opslimit, memlimit)
	res := argon2.Key(pw.pw, salt, time, memory, threads, uint32(out))
	h = append(dst, res...)
	godium.Wipe(res)
	return
}

// Str implements godium.PwHash.
func (pw *Argon2i) Str(dst []byte, opslimit, memlimit uint64) (h []byte) {
	h = pw.StrParallel(dst, opslimit, memlimit, 1)
	return
}

// StrParallel functions like Str, but accepts an additional parameter that
// specifies the level of parallelism for the generation of the hash string.
func (pw *Argon2i) StrParallel(dst []byte, opslimit, memlimit uint64, threads uint8) (h []byte) {
	// todo generate Salt, outlen
	h = pw.HashParallel(dst, nil, 0, opslimit, memlimit, threads)
	// TODO turn h into a string of form $argoni$parems$base64(hash)$
	return
}

// StrVerify implements godium.PwHash.
func (pw *Argon2i) StrVerify(h []byte) (valid bool) {
	valid = pw.StrVerifyParallel(h, 1)
	return
}

// StrVerifyParallel functions like StrVerify, but accepts an additional
// parameter that specifies the level of parallelism for the verification of the
// hash.
func (pw *Argon2i) StrVerifyParallel(h []byte, threads uint8) (valid bool) {
	// pw.StrParallel()
	// TODO extract salt/opslimit/memlimit from h
	// return subtle.ConstantTimeCompare(result, h) == 1
	return
}

func (pw *Argon2i) BytesMin() int            { return Argon2i_BytesMin }
func (pw *Argon2i) BytesMax() int            { return Argon2i_BytesMax }
func (pw *Argon2i) PasswdMin() int           { return Argon2i_PasswdMin }
func (pw *Argon2i) PasswdMax() int           { return Argon2i_PasswdMax }
func (pw *Argon2i) MemLimitMin() int         { return Argon2i_MemLimitMin }
func (pw *Argon2i) MemLimitMax() int         { return Argon2i_MemLimitMax }
func (pw *Argon2i) MemLimitInteractive() int { return Argon2i_MemLimitInteractive }
func (pw *Argon2i) MemLimitModerate() int    { return Argon2i_MemLimitSensitive }
func (pw *Argon2i) MemLimitSensitive() int   { return Argon2i_MemLimitSensitive }
func (pw *Argon2i) OpsLimitMin() int         { return Argon2i_OpsLimitMin }
func (pw *Argon2i) OpsLimitMax() int         { return Argon2i_OpsLimitMax }
func (pw *Argon2i) OpsLimitInteractive() int { return Argon2i_OpsLimitInteractive }
func (pw *Argon2i) OpsLimitModerate() int    { return Argon2i_OpsLimitSensitive }
func (pw *Argon2i) OpsLimitSensitive() int   { return Argon2i_OpsLimitSensitive }
func (pw *Argon2i) SaltBytes() int           { return Argon2i_SaltBytes }
func (pw *Argon2i) StrBytes() int            { return Argon2i_StrBytes }
func (pw *Argon2i) StrPrefix() string        { return Argon2i_StrPrefix }
