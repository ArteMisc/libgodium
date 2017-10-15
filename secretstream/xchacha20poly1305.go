// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package secretstream

import (
	"encoding/binary"
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/aead"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/onetimeauth"
	"go.artemisc.eu/godium/random"
	"go.artemisc.eu/godium/stream"
)

const (
	XChacha20Poly1305_ABytes       = 1 + aead.XChacha20Poly1305Ietf_ABytes
	XChacha20Poly1305_HeaderBytes  = aead.XChacha20Poly1305Ietf_NPubBytes
	XChacha20Poly1305_KeyBytes     = aead.XChacha20Poly1305Ietf_KeyBytes
	XChacha20Poly1305_CounterBytes = 4
	XChacha20Poly1305_INonceBytes  = 8
	XChacha20Poly1305_TAG_MESSAGE  = 0x00
	XChacha20Poly1305_TAG_PUSH     = 0x01
	XChacha20Poly1305_TAG_REKEY    = 0x02
	XChacha20Poly1305_TAG_FINAL    = XChacha20Poly1305_TAG_PUSH | XChacha20Poly1305_TAG_REKEY
)

var (
	// rand reader
	rand = random.New()

	_pad0 [16]byte
)

//
type XChacha20Poly1305Tag byte

func (tag XChacha20Poly1305Tag) IsMessage() bool {
	return tag == XChacha20Poly1305_TAG_MESSAGE
}

func (tag XChacha20Poly1305Tag) ShouldReKey() bool {
	return tag&XChacha20Poly1305_TAG_REKEY != 0
}

func (tag XChacha20Poly1305Tag) IsFinal() bool {
	return tag&XChacha20Poly1305_TAG_FINAL != 0
}

// XChacha20Poly1305
type XChacha20Poly1305 struct {
	key    [XChacha20Poly1305_KeyBytes]byte
	nonce  [stream.Chacha20Ietf_NonceBytes]byte
	stream godium.Stream
	poly   *onetimeauth.Poly1305
	pad    [8]byte
}

// NewXChacha20Poly1305
func NewXChacha20Poly1305() (s *XChacha20Poly1305) {
	s = new(XChacha20Poly1305)
	return
}

//
func (s *XChacha20Poly1305) stateCounter() []byte {
	return s.nonce[:XChacha20Poly1305_CounterBytes]
}

//
func (s *XChacha20Poly1305) stateINonce() []byte {
	return s.nonce[XChacha20Poly1305_CounterBytes:]
}

// resetPad clears the pad by setting it to 0
func (s *XChacha20Poly1305) resetPad() {
	for i := range s.pad {
		s.pad[i] = 0
	}
}

// resetCounter starts the counter at 1
func (s *XChacha20Poly1305) resetCounter() {
	for i := 0; i < XChacha20Poly1305_CounterBytes; i++ {
		s.nonce[i] = 0
	}
	s.nonce[0] = 1
}

// Wipe clears the state
func (s *XChacha20Poly1305) Wipe() {
	defer godium.Wipe(s.key[:])
	defer godium.Wipe(s.nonce[:])
	defer s.poly.Wipe()
	defer s.stream.Wipe()
}

// InitPush
func (s *XChacha20Poly1305) InitPush(dst []byte, key godium.Key) (header []byte) {
	header = core.AllocDst(dst, XChacha20Poly1305_HeaderBytes)

	rand.Buf(header)
	core.HChacha20(s.key[:0], header, key, nil)
	copy(s.stateINonce(), header[core.HChacha20_InputBytes:])

	s.resetCounter()
	s.resetPad()

	if s.stream == nil {
		s.stream = stream.NewChacha20Ietf(s.key[:], s.nonce[:])
	} else {
		s.stream.ReKey(s.key[:], s.nonce[:])
	}

	return
}

// InitPull
func (s *XChacha20Poly1305) InitPull(header []byte, key godium.Key) (err error) {
	if len(header) < XChacha20Poly1305_HeaderBytes {
		err = godium.ErrBufferTooShort
		return
	}

	core.HChacha20(s.key[:0], header, key, nil)
	copy(s.stateINonce(), header[core.HChacha20_InputBytes:])

	s.resetCounter()
	s.resetPad()

	if s.stream == nil {
		s.stream = stream.NewChacha20Ietf(s.key[:], s.nonce[:])
	} else {
		s.stream.ReKey(s.key[:], s.nonce[:])
	}

	return
}

// ReKey
func (s *XChacha20Poly1305) ReKey() {
	// TODO can this be done without remporary values?
	var newKeyAndInonce [stream.Chacha20Ietf_KeyBytes + XChacha20Poly1305_INonceBytes]byte
	copy(newKeyAndInonce[:stream.Chacha20Ietf_KeyBytes], s.key[:])
	copy(newKeyAndInonce[stream.Chacha20Ietf_KeyBytes:], s.stateINonce())

	// TODO can this be cleaned up by SEEK-ing to 0?
	s.stream.ReKey(s.key[:], s.nonce[:])
	s.stream.XORKeyStream(newKeyAndInonce[:], newKeyAndInonce[:])

	copy(s.key[:], newKeyAndInonce[:stream.Chacha20Ietf_KeyBytes])
	copy(s.stateINonce(), newKeyAndInonce[stream.Chacha20Ietf_KeyBytes:])

	s.resetCounter()
}

// Push
func (s *XChacha20Poly1305) Push(dst, plain, ad []byte, t byte) (cipher []byte) {
	var block [stream.Chacha20Ietf_BlockBytes]byte
	var mac, c []byte
	var slen [8]byte
	var mlen uint64 = uint64(len(plain))
	var adlen uint64 = uint64(len(ad))
	var tag XChacha20Poly1305Tag = XChacha20Poly1305Tag(t)

	cipher = core.AllocDst(dst, mlen+XChacha20Poly1305_ABytes)

	defer godium.Wipe(block[:])
	defer godium.Wipe(mac[:])
	defer s.poly.Wipe()

	s.stream.ReKey(s.key[:], s.nonce[:])
	s.stream.KeyStream(block[:])
	s.poly.ReKey(block[:])
	godium.Wipe(block[:])

	s.poly.Write(ad)
	s.poly.Write(_pad0[:(0x10-adlen)&0xf])

	block[0] = t
	s.stream.XORKeyStream(block[:], block[:])
	s.poly.Write(block[:])
	cipher[0] = block[0]

	c = cipher[1:]
	s.stream.XORKeyStream(c, plain)
	s.poly.Write(c[:mlen])
	s.poly.Write(_pad0[:(0x10-(stream.Chacha20Ietf_BlockBytes+mlen))&0xf])

	binary.LittleEndian.PutUint64(slen[:], adlen)
	s.poly.Write(slen[:])
	binary.LittleEndian.PutUint64(slen[:], stream.Chacha20Ietf_BlockBytes+mlen)
	s.poly.Write(slen[:])

	mac = c[mlen:mlen]
	mac = s.poly.Sum(mac)

	iNonce := s.stateINonce()
	for i := range iNonce {
		iNonce[i] ^= mac[i]
	}

	core.Increment(s.stateCounter())
	if tag.ShouldReKey() || core.IsZero(s.stateCounter()) {
		s.ReKey()
	}

	return
}

// Pull
func (s *XChacha20Poly1305) Pull(dst, cipher, ad []byte) (plain []byte, tag byte, err error) {
	var block [stream.Chacha20Ietf_BlockBytes]byte
	var slen [8]byte
	var c, storedMac []byte
	var adlen = uint64(len(ad))
	var mlen = uint64(len(cipher) - XChacha20Poly1305_ABytes)

	if len(cipher) < XChacha20Poly1305_ABytes {
		err = godium.ErrCipherTooShort
		return
	}

	defer godium.Wipe(block[:])
	defer s.poly.Wipe()

	s.stream.ReKey(s.key[:], s.nonce[:])
	s.stream.KeyStream(block[:])
	s.poly.ReKey(block[:])
	godium.Wipe(block[:])

	s.poly.Write(ad)
	s.poly.Write(_pad0[:(0x10-adlen)&0xf])

	block[0] = cipher[0]
	s.stream.XORKeyStream(block[:], block[:])
	tag = block[0]
	block[0] = cipher[0]
	s.poly.Write(block[:])

	c = cipher[1:]
	s.poly.Write(c[:mlen])
	s.poly.Write(_pad0[:(0x10-(stream.Chacha20Ietf_BlockBytes+mlen))&0xf])

	binary.LittleEndian.PutUint64(slen[:], adlen)
	s.poly.Write(slen[:])
	binary.LittleEndian.PutUint64(slen[:], stream.Chacha20Ietf_BlockBytes+mlen)
	s.poly.Write(slen[:])

	storedMac = c[mlen:]
	if !s.poly.Verify(storedMac) {
		err = godium.ErrForgedOrCorrupted
		return
	}

	plain = core.AllocDst(dst, mlen)

	s.stream.XORKeyStream(plain, c)
	iNonce := s.stateINonce()
	for i := range iNonce {
		iNonce[i] ^= storedMac[i]
	}

	core.Increment(s.stateCounter())
	if XChacha20Poly1305Tag(tag).ShouldReKey() ||
		core.IsZero(s.stateCounter()) {
		s.ReKey()
	}

	return
}

func (s *XChacha20Poly1305) ABytes() int       { return XChacha20Poly1305_ABytes }
func (s *XChacha20Poly1305) HeaderBytes() int  { return XChacha20Poly1305_HeaderBytes }
func (s *XChacha20Poly1305) KeyBytes() int     { return XChacha20Poly1305_KeyBytes }
func (s *XChacha20Poly1305) CounterBytes() int { return XChacha20Poly1305_CounterBytes }
func (s *XChacha20Poly1305) INonceBytes() int  { return XChacha20Poly1305_INonceBytes }
func (s *XChacha20Poly1305) TAG_MESSAGE() byte { return XChacha20Poly1305_TAG_MESSAGE }
func (s *XChacha20Poly1305) TAG_PUSH() byte    { return XChacha20Poly1305_TAG_PUSH }
func (s *XChacha20Poly1305) TAG_REKEY() byte   { return XChacha20Poly1305_TAG_REKEY }
func (s *XChacha20Poly1305) TAG_FINAL() byte   { return XChacha20Poly1305_TAG_FINAL }
