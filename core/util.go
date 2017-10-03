// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package core

// AllocDst
func AllocDst(dst []byte, size uint64) (out []byte) {
	l := uint64(len(dst))
	c := uint64(cap(dst))

	if c-l < size {
		out = make([]byte, size)
	} else {
		out = dst[l : l+size]
	}
	return
}

// Copy
func Copy(buf []byte, n uint64) (cpy []byte) {
	cpy = make([]byte, n)
	copy(cpy, buf)
	return
}
