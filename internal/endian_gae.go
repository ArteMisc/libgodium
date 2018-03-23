// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//+build appengine

package internal

import (
	"encoding/binary"
)

//
var NativeEndian binary.ByteOrder = binary.LittleEndian
