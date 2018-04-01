package generichash

import (
	"testing"

	"reflect"
)

// Regression test for https://github.com/ArteMisc/libgodium/issues/2
func TestNewBlake2bSaltPersonal(t *testing.T) {
	const (
		hashSz = 1
		testSliceSz = 5
	)
	sliceGen := func(b byte) []byte {
		bs := make([]byte, testSliceSz)
		for i := range bs {
			bs[i] = b
		}
		return bs
	}

	var (
		key1 = sliceGen(1)
		key2 = sliceGen(2)

		personal1 = sliceGen(11)
		personal2 = sliceGen(22)

		salt1 = sliceGen(111)
		salt2 = sliceGen(222)
	)

	bs1 := NewBlake2bSaltPersonal(hashSz, key1, personal1, salt1).Hash.Sum(nil)
	bs2 := NewBlake2bSaltPersonal(hashSz, key2, personal2, salt2).Hash.Sum(nil)

	if reflect.DeepEqual(bs1, bs2) {
		t.Error("Keys derived from two different sets of key/personal/salt data should not be equal")
	}
}
