package main

import (
	"bytes"
	"crypto/aes"
	"log"
	"math/rand"
)

func xorEncryptBytes(one, key []byte) []byte {
	var result bytes.Buffer
	keyLen := len(key)
	bufLen := len(one)

	for i := 0; i < bufLen; i += keyLen {
		for k := 0; k < keyLen && i+k < bufLen; k++ {
			result.WriteByte(one[i+k] ^ key[k])
		}
	}

	return result.Bytes()
}

func AddPadding(data []byte, blocksize int) []byte {
	var padded bytes.Buffer
	var pads int

	padded.Write(data)

	if len(data) < blocksize {
		pads = blocksize - len(data)
	} else {
		pads = blocksize - (len(data) % blocksize)
	}

	if pads == 0 {
		pads = 16
	}

	for i := 0; i < pads; i++ {
		padded.WriteByte(byte(pads))
	}

	return padded.Bytes()
}

func StripPadding(data []byte) []byte {
	length := int(data[len(data)-1])
	stripped := data[:len(data)-length]
	return stripped
}

func VerifyPadding(data []byte) bool {
	length := len(data)
	pads := data[length-1]
	expectedPadding := make([]byte, pads)
	for i, _ := range expectedPadding {
		expectedPadding[i] = pads
	}
	return bytes.Equal(expectedPadding, data[length-int(pads):length-1])
}

func RandomKey(length int) []byte {
	var key bytes.Buffer
	for ; length > 0; length-- {
		key.WriteByte(byte(rand.Int()))
	}
	return key.Bytes()
}

func CBCEncrypt(key, data, IV []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	encrypter := NewCBCEncrypter(c, IV)
	p := make([]byte, len(data))
	encrypter.CryptBlocks(p, data)

	return p
}

func ECBDecrypt(key, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	decrypter := NewECBDecrypter(c)
	p := make([]byte, len(data))
	decrypter.CryptBlocks(p, data)

	return p
}

func CBCDecrypt(key, data, IV []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	decrypter := NewCBCDecrypter(c, IV)
	p := make([]byte, len(data))
	decrypter.CryptBlocks(p, data)

	return p
}

func ECBEncrypt(key, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	encrypter := NewECBEncrypter(c)
	p := make([]byte, len(data))
	encrypter.CryptBlocks(p, data)

	return p
}
