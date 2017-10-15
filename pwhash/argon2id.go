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
