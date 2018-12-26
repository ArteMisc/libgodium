// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/subtle"
)

// IsZero returns true if all bytes in buf are 0.
func IsZero(buf []byte) (zero bool) {
	var d uint8
	for i := range buf {
		d |= buf[i]
	}
	return (1 & ((d - 1) >> 8)) != 1
}

// Increment adds 1 to the value of buf represented as a number in little endian
// form.
//
// TODO implement in ASM?
func Increment(buf []byte) {
	var c uint16
	for i := range buf {
		c += uint16(buf[i])
		buf[i] = uint8(c)
		c >>= 8
	}
}

// Equals TODO
func Equals(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
