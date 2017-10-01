package core

import (
	"unsafe"

	"golang.org/x/crypto/salsa20/salsa"
)

const (
	HSalsa20_OutputBytes = 32
	HSalsa20_InputBytes  = 16
	HSalsa20_KeyBytes    = 32
	HSalsa20_ConstBytes  = 16
)

// HSalsa20 implements the salsa20 hash function
func HSalsa20(dst, nonce, key, sigma []byte) (out []byte) {
	if len(sigma) == 0 {
		sigma = salsa.Sigma[:]
	} else if len(sigma) < HSalsa20_ConstBytes {
		panic("invalid sigma size")
	}

	if len(nonce) < 16 {
		panic("invalid nonce size")
	}

	out = append(dst, make([]byte, HSalsa20_OutputBytes)...)

	salsa.HSalsa20(
		(*[HSalsa20_OutputBytes]byte)(unsafe.Pointer(&out[0])),
		(*[HSalsa20_InputBytes]byte)(unsafe.Pointer(&nonce[0])),
		(*[HSalsa20_KeyBytes]byte)(unsafe.Pointer(&key[0])),
		(*[HSalsa20_ConstBytes]byte)(unsafe.Pointer(&sigma[0])))

	return
}
