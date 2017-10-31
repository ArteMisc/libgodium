// Copyright 2017, Project ArteMisc
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package box

import (
	"go.artemisc.eu/godium"
	"go.artemisc.eu/godium/core"
	"go.artemisc.eu/godium/internal"
	"go.artemisc.eu/godium/scalarmult"
	"go.artemisc.eu/godium/secretbox"
)

const (
	Curve25519XSalsa20Poly1305_PublicKeyBytes = 32
	Curve25519XSalsa20Poly1305_SecretKeyBytes = 32
	Curve25519XSalsa20Poly1305_MacBytes       = 16
	Curve25519XSalsa20Poly1305_NonceBytes     = 24
	Curve25519XSalsa20Poly1305_SeedBytes      = 32
	Curve25519XSalsa20Poly1305_BeforeNmBytes  = 32
)

// Curve25519XSalsa20Poly1305
type Curve25519XSalsa20Poly1305 struct {
	godium.PrivateKey
	godium.PublicKey
}

//
func NewCurve25519XSalsa20Poly1305(private, public []byte) (box godium.Box) {
	box = &Curve25519XSalsa20Poly1305{
		PrivateKey: internal.Copy(private, Curve25519XSalsa20Poly1305_SecretKeyBytes),
		PublicKey:  internal.Copy(public, Curve25519XSalsa20Poly1305_PublicKeyBytes),
	}
	return
}

func (b *Curve25519XSalsa20Poly1305) Wipe() {
	godium.Wipe(b.PrivateKey)
}

func (b *Curve25519XSalsa20Poly1305) SealDetached(dst, dstMac, nonce, plain []byte, remote godium.PublicKey) (cipher, mac []byte, err error) {
	sb, err := b.BeforeNM(remote)
	if err != nil {
		return
	}
	defer sb.Wipe()
	cipher, mac = sb.SealDetached(dst, dstMac, nonce, plain)
	return
}

func (b *Curve25519XSalsa20Poly1305) Seal(dst, nonce, plain []byte, remote godium.PublicKey) (cipher []byte, err error) {
	sb, err := b.BeforeNM(remote)
	if err != nil {
		return
	}
	defer sb.Wipe()
	cipher = sb.Seal(dst, nonce, plain)
	return
}

func (b *Curve25519XSalsa20Poly1305) OpenDetached(dst, nonce, cipher, mac []byte, remote godium.PublicKey) (plain []byte, err error) {
	sb, err := b.BeforeNM(remote)
	if err != nil {
		return
	}
	defer sb.Wipe()
	plain, err = sb.OpenDetached(dst, nonce, cipher, mac)
	return
}

func (b *Curve25519XSalsa20Poly1305) Open(dst, nonce, cipher []byte, remote godium.PublicKey) (plain []byte, err error) {
	sb, err := b.BeforeNM(remote)
	if err != nil {
		return
	}
	defer sb.Wipe()
	plain, err = sb.Open(dst, nonce, cipher)
	return
}

func (b *Curve25519XSalsa20Poly1305) BeforeNM(remote godium.PublicKey) (sb godium.SecretBox, err error) {
	var s []byte
	var key []byte
	var zero [16]byte

	s, err = scalarmult.Curve25519(make([]byte, 0, 32), b.PrivateKey, remote)
	if err != nil {
		return
	}
	key = core.HSalsa20(make([]byte, 0, 32), zero[:], s, core.Salsa20Sigma[:])

	sb = secretbox.NewXSalsa20Poly1305(key[:])
	return
}

func (b *Curve25519XSalsa20Poly1305) PublicKeyBytes() int {
	return Curve25519XSalsa20Poly1305_PublicKeyBytes
}
func (b *Curve25519XSalsa20Poly1305) SecretKeyBytes() int {
	return Curve25519XSalsa20Poly1305_SecretKeyBytes
}
func (b *Curve25519XSalsa20Poly1305) MacBytes() int   { return Curve25519XSalsa20Poly1305_MacBytes }
func (b *Curve25519XSalsa20Poly1305) NonceBytes() int { return Curve25519XSalsa20Poly1305_NonceBytes }
func (b *Curve25519XSalsa20Poly1305) SeedBytes() int  { return Curve25519XSalsa20Poly1305_SeedBytes }
func (b *Curve25519XSalsa20Poly1305) BeforeNmBytes() int {
	return Curve25519XSalsa20Poly1305_BeforeNmBytes
}
