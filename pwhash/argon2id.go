// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pwhash

import (
	"math"
)

const (
	Argon2id_Alg                 = 2
	Argon2id_BytesMin            = 16
	Argon2id_BytesMax            = math.MaxUint32
	Argon2id_PasswdMin           = 0
	Argon2id_PasswdMax           = 4294967295
	Argon2id_MemLimitMin         = 8192
	Argon2id_MemLimitMax         = 4398046510080
	Argon2id_MemLimitInteractive = 67108864
	Argon2id_MemLimitModerate    = 268435456
	Argon2id_MemLimitSensitive   = 1073741824
	Argon2id_OpsLimitMin         = 1
	Argon2id_OpsLimitMax         = 4294967295
	Argon2id_OpsLimitInteractive = 2
	Argon2id_OpsLimitModerate    = 3
	Argon2id_OpsLimitSensitive   = 4
	Argon2id_SaltBytes           = 16
	Argon2id_StrBytes            = 128
	Argon2id_StrPrefix           = "$argon2id$"
)

type Argon2id struct {
	pw []byte
}

func (pw *Argon2id) BytesMin() int            { return Argon2id_BytesMin }
func (pw *Argon2id) BytesMax() int            { return Argon2id_BytesMax }
func (pw *Argon2id) PasswdMin() int           { return Argon2id_PasswdMin }
func (pw *Argon2id) PasswdMax() int           { return Argon2id_PasswdMax }
func (pw *Argon2id) MemLimitMin() int         { return Argon2id_MemLimitMin }
func (pw *Argon2id) MemLimitMax() int         { return Argon2id_MemLimitMax }
func (pw *Argon2id) MemLimitInteractive() int { return Argon2id_MemLimitInteractive }
func (pw *Argon2id) MemLimitModerate() int    { return Argon2id_MemLimitSensitive }
func (pw *Argon2id) MemLimitSensitive() int   { return Argon2id_MemLimitSensitive }
func (pw *Argon2id) OpsLimitMin() int         { return Argon2id_OpsLimitMin }
func (pw *Argon2id) OpsLimitMax() int         { return Argon2id_OpsLimitMax }
func (pw *Argon2id) OpsLimitInteractive() int { return Argon2id_OpsLimitInteractive }
func (pw *Argon2id) OpsLimitModerate() int    { return Argon2id_OpsLimitSensitive }
func (pw *Argon2id) OpsLimitSensitive() int   { return Argon2id_OpsLimitSensitive }
func (pw *Argon2id) SaltBytes() int           { return Argon2id_SaltBytes }
func (pw *Argon2id) StrBytes() int            { return Argon2id_StrBytes }
func (pw *Argon2id) StrPrefix() string        { return Argon2id_StrPrefix }
