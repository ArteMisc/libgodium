package hchacha

import (
	"unsafe"

	"git.schwanenlied.me/yawning/chacha20.git"
)

const (
	OutputBytes = 32
	InputBytes  = 16
	KeyBytes    = 32
	ConstBytes  = 16
)

// HChacha20 implements the chacha20 hash function
func HChacha20(dst, nonce, key, sigma []byte) (out []byte) {
	if len(sigma) == 0 {
		// todo set to default sigma
	} else {
		// for now, not supported
		panic("HChacha20: using own sigma not yet supported")
	}

	if len(nonce) < InputBytes {
		panic("invalid nonce size")
	}

	out = append(dst, make([]byte, OutputBytes)...)

	chacha20.HChaCha(key,
		(*[InputBytes]byte)(unsafe.Pointer(&nonce[0])),
		(*[OutputBytes]byte)(unsafe.Pointer(&out[0])))

	return
}
