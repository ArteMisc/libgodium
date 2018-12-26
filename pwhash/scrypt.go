// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pwhash

import (
	"bytes"
	"crypto/subtle"
	"math"

	//"golang.org/x/crypto/scrypt"

	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/internal"
)

const (
	Scrypt_BytesMin            = 16
	Scrypt_BytesMax            = 0x1fffffffe0
	Scrypt_PasswdMin           = 0
	Scrypt_PasswdMax           = math.MaxUint32
	Scrypt_MemLimitMin         = 16777216
	Scrypt_MemLimitMax         = 68719476736
	Scrypt_MemLimitInteractive = 16777216
	Scrypt_MemLimitSensitive   = 1073741824
	Scrypt_OpsLimitMin         = 32768
	Scrypt_OpsLimitMax         = 4294967295
	Scrypt_OpsLimitInteractive = 524288
	Scrypt_OpsLimitSensitive   = 33554432
	Scrypt_SaltBytes           = 32
	Scrypt_StrBytes            = 102
	Scrypt_StrPrefix           = "$7$"
)

// scryptStrPrefix is the []byte copy of the Scrypt_StrPrefix constant for
// internal use.
var scryptStrPrefix = []byte(Scrypt_StrPrefix)

// Scrypt implements godium.PwHash, based on the Scrypt password hashing
// function.
type Scrypt struct {
	pw []byte
}

// NewScrypt creates a new instance of Scrypt with pw as the given password.
func NewScrypt(pw []byte) (ph godium.PwHash) {
	ph = &Scrypt{
		pw: internal.Copy(pw, uint64(len(pw))),
	}
	return
}

// Wipe implements godium.PwHash.
func (pw *Scrypt) Wipe() {
	godium.Wipe(pw.pw)
}

// pickParams converts the provided opslimit and memlimit values into Scrypt's
// internally used n, p and r values.
func (pw *Scrypt) pickParams(opslimit, memlimit uint64) (NLog2, p, r uint64) {
	var maxN, maxrp uint64

	if opslimit < 32768 {
		opslimit = 32768
	}

	r = 8

	if opslimit < memlimit/32 {
		p = 1
		maxN = opslimit / (r * 4)
		for NLog2 = 1; NLog2 < 63; NLog2++ {
			if (1 << NLog2) > (maxN / 2) {
				break
			}
		}

		return
	}

	maxN = memlimit / (r * 128)
	for NLog2 = 1; NLog2 < 63; NLog2++ {
		if (1 << NLog2) > (maxN / 2) {
			break
		}
	}

	maxrp = (opslimit / 4) / (1 << NLog2)
	/* LCOV_EXCL_START */
	if maxrp > 0x3fffffff {
		maxrp = 0x3fffffff
	}

	p = maxrp / r

	return
}

// extractParams will extract the
func (pw *Scrypt) extractParams(stored []byte) (opslimit, memlimit uint64, err error) {
	if !bytes.HasPrefix(stored, scryptStrPrefix) {
		err = ErrWrongAlg
		return
	}

	return
}

// Hash
func (pw *Scrypt) Hash(dst, salt []byte, out, opslimit, memlimit uint64) (h []byte, err error) {
	return
}

// Str
func (pw *Scrypt) Str(dst []byte, opslimit, memlimit uint64) (h []byte, err error) {
	h = internal.AllocDst(dst, Scrypt_StrBytes)[:0]
	salt := make([]byte, Scrypt_SaltBytes)

	err = reader.Buf(salt)
	if err != nil {
		return
	}

	//nlog2, p, r := pw.pickParams(opslimit, memlimit)
	//key, _ := scrypt.Key(pw.pw, salt, 1<<nlog2, r, p, keylen)

	return
}

// StrVerify
func (pw *Scrypt) StrVerify(stored []byte) (err error) {
	opsLimit, memLimit, err := pw.extractParams(stored)
	if err != nil {
		return
	}

	h, err := pw.Str(make([]byte, 0, Scrypt_StrBytes), opsLimit, memLimit)
	if err != nil {
		return
	}

	if subtle.ConstantTimeCompare(stored, h) != 0 {
		err = ErrWrongPassword
	}

	return
}

func (pw *Scrypt) BytesMin() int            { return Scrypt_BytesMin }
func (pw *Scrypt) BytesMax() int            { return Scrypt_BytesMax }
func (pw *Scrypt) PasswdMin() int           { return Scrypt_PasswdMin }
func (pw *Scrypt) PasswdMax() int           { return Scrypt_PasswdMax }
func (pw *Scrypt) MemLimitMin() int         { return Scrypt_MemLimitMin }
func (pw *Scrypt) MemLimitMax() int         { return Scrypt_MemLimitMax }
func (pw *Scrypt) MemLimitInteractive() int { return Scrypt_MemLimitInteractive }
func (pw *Scrypt) MemLimitModerate() int    { return Scrypt_MemLimitSensitive }
func (pw *Scrypt) MemLimitSensitive() int   { return Scrypt_MemLimitSensitive }
func (pw *Scrypt) OpsLimitMin() int         { return Scrypt_OpsLimitMin }
func (pw *Scrypt) OpsLimitMax() int         { return Scrypt_OpsLimitMax }
func (pw *Scrypt) OpsLimitInteractive() int { return Scrypt_OpsLimitInteractive }
func (pw *Scrypt) OpsLimitModerate() int    { return Scrypt_OpsLimitSensitive }
func (pw *Scrypt) OpsLimitSensitive() int   { return Scrypt_OpsLimitSensitive }
func (pw *Scrypt) SaltBytes() int           { return Scrypt_SaltBytes }
func (pw *Scrypt) StrBytes() int            { return Scrypt_StrBytes }
func (pw *Scrypt) StrPrefix() string        { return Scrypt_StrPrefix }
