# libgodium
Pure Go implementation of cryptographic APIs found in libsodium. The
implementations are compatible with libsodium 1.0.15.

## Import

```bash
go get go.artemisc.eu/godium
```

## Godoc
[https://godoc.org/go.artemisc.eu/godium](https://godoc.org/go.artemisc.eu/godium "Godium godocs")

## License
Unless otherwise specified, code present in this library is licensed under the
[Mozilla Public License Version v2.0](https://www.mozilla.org/en-US/MPL/2.0/ "MPL v2.0").

## Credits
This library is built upon existing cryptographic implementations.

* The Go Authors (crypto and golang/x/crypto packages)
* [git.schwanenlied.me/yawning/chacha20](https://godoc.org/git.schwanenlied.me/yawning/chacha20)
* [git.schwanenlied.me/yawning/poly1305](https://godoc.org/git.schwanenlied.me/yawning/poly1305)

#### Implemented APIs
* AEAD
    * aes256gcm
    * chacha20poly1305
    * chacha20poly1305\_ietf
    * xchacha20poly1305\_ietf
* Auth
    * hmacsha256
    * hmacsha512
    * hmacsha256256
* Box
    * curve25519xchacha20poly1305
    * curve25519xsalsa20poly1305
* Core
    * hchacha20
    * hsalsa20
    * salsa20 (TODO: amd64 implementation)
* Generic Hash
    * blake2b
* Hash
    * sha256
    * sha512
* KDF (Key Derivation Function)
    * TODO blake2b
* KX (Key Exchange)
    * TODO x25519blake2b
* OneTimeAuth
    * poly1305
* Password Hash
    * TODO argon2id
    * TODO argon2i
    * TODO scrypt
* Random bytes
    * sodium randombytes
* Scalar Mult
    * curve25519
* Secret Box
    * xchacha20poly1305
    * xsalsa20poly1305
* Secret Stream
    * TODO xchacha20poly1305
* Short Hash
    * siphash24
    * siphashx24
* Signature
    * ed25519
    * ed25519ph
* Stream
    * chacha20
    * chacha20 ietf
    * xchacha20
    * TODO salsa208
    * TODO salsa2012
    * salsa20
    * xsalsa20
* Misc/Util
    * TODO constant time hex encode/decode
    * TODO constant time base64 encode/decode
