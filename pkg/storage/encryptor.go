package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type Encryptor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

type encryptor struct {
	block cipher.Block
}

func NewDefaultEncryptor(key []byte) (Encryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &encryptor{block: block}, nil
}

func (e encryptor) Encrypt(src []byte) ([]byte, error) {
	iv := GenerateRandomKey(e.block.BlockSize())
	ctrXOR(e.block, iv, src, src)
	return append(iv, src...), nil
}

func (e encryptor) Decrypt(src []byte) ([]byte, error) {
	size := e.block.BlockSize()
	if len(src) < size {
		return nil, errors.New("[Decrypt] block size is greater than src length")
	}
	iv := src[:size]
	src = src[size:]
	ctrXOR(e.block, iv, src, src)
	return src, nil
}

func ctrXOR(block cipher.Block, iv, src, dst []byte) {
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(src, dst)
}

func GenerateRandomKey(size int) []byte {
	key := make([]byte, size)
	_, _ = rand.Read(key)
	return key
}
