package main

import (
	"crypto/cipher"
)

type cbc struct {
	b		cipher.Block
	blockSize	int
	IV		[]byte
}

func newCBC(b cipher.Block, IV []byte) *cbc {
	return &cbc{
		b:		b,
		blockSize: 	b.BlockSize(),
		IV:		IV,
	}
}

type cbcEncrypter cbc

func NewCBCEncrypter(b cipher.Block, IV []byte) cipher.BlockMode {
	return (*cbcEncrypter)(newCBC(b, IV))
}

func (x *cbcEncrypter) BlockSize() int { return x.blockSize }

func (x *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	blockToEncrypt := xorEncryptBytes(src[:x.blockSize], x.IV)
	for len(src) > 0 {
		x.b.Encrypt(dst, blockToEncrypt)
		src = src[x.blockSize:]
		blockToEncrypt = xorEncryptBytes(dst[:x.blockSize], src[:x.blockSize])
		dst = dst[x.blockSize:]
	}
}

type cbcDecrypter cbc

func NewCBCDecrypter(b cipher.Block, IV []byte) cipher.BlockMode {
	return (*cbcDecrypter)(newCBC(b, IV))
}

func (x *cbcDecrypter) BlockSize() int { return x.blockSize }

func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	pos := len(src) - x.blockSize
	for pos >= 0 {
		var block []byte
		x.b.Decrypt(dst[pos:], src[pos:pos+x.blockSize])
		if pos == 0 {
			block = x.IV
		} else {
			block = src[pos-x.blockSize:pos]
		}
		xored := xorEncryptBytes(dst[pos:pos+x.blockSize], block)
		copy(dst[pos:pos+x.blockSize], xored)
		pos -= x.blockSize
	}
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
