package hsalsa

import (
	"unsafe"

	"golang.org/x/crypto/salsa20/salsa"
)

const (
	OutputBytes = 32
	InputBytes  = 16
	KeyBytes    = 32
	ConstBytes  = 16
)

// HSalsa20 implements the salsa20 hash function
func HSalsa20(dst, nonce, key, sigma []byte) (out []byte) {
	if len(sigma) == 0 {
		sigma = salsa.Sigma[:]
	} else if len(sigma) < ConstBytes {
		panic("invalid sigma size")
	}

	if len(nonce) < 16 {
		panic("invalid nonce size")
	}

	out = append(dst, make([]byte, OutputBytes)...)

	salsa.HSalsa20(
		(*[OutputBytes]byte)(unsafe.Pointer(&out[0])),
		(*[InputBytes]byte)(unsafe.Pointer(&nonce[0])),
		(*[KeyBytes]byte)(unsafe.Pointer(&key[0])),
		(*[ConstBytes]byte)(unsafe.Pointer(&sigma[0])))

	return
}
