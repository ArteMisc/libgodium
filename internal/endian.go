// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package internal

import (
	"encoding/binary"
	"unsafe"
)

//
var NativeEndian binary.ByteOrder

//
func init() {
	var i uint64 = 0x1
	bs := (*[8]byte)(unsafe.Pointer(&i))

	if bs[0] == 0 {
		NativeEndian = binary.BigEndian
	} else {
		NativeEndian = binary.LittleEndian
	}
}
