package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type Encryptor interface {
	EncryptStream(w io.Writer) (io.Writer, error)
	DecryptStream(r io.Reader) (io.Reader, error)
	//Encrypt(data []byte) ([]byte, error)
	//Decrypt(data []byte) ([]byte, error)
}

type aesEncryptor struct {
	block cipher.Block
}

func NewDefaultEncryptor(key []byte) (Encryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &aesEncryptor{block: block}, nil
}

func (e aesEncryptor) EncryptStream(w io.Writer) (io.Writer, error) {
	iv := GenerateRandomKey(e.block.BlockSize())
	if _, err := w.Write(iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(e.block, iv)
	return &cipher.StreamWriter{S: stream, W: w}, nil
}

func (e aesEncryptor) DecryptStream(r io.Reader) (io.Reader, error) {
	iv := make([]byte, e.block.BlockSize())
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(e.block, iv)
	return &cipher.StreamReader{S: stream, R: r}, nil
}

//
//func (e aesEncryptor) Decrypt(src []byte) ([]byte, error) {
//	size := e.block.BlockSize()
//	if len(src) < size {
//		return nil, errors.New("[Decrypt] block size is greater than src length")
//	}
//	iv := src[:size]
//	src = src[size:]
//	ctrXOR(e.block, iv, src, src)
//	return src, nil
//}
//
//func (e aesEncryptor) Encrypt(src []byte) ([]byte, error) {
//	iv := GenerateRandomKey(e.block.BlockSize())
//	ctrXOR(e.block, iv, src, src)
//	return append(iv, src...), nil
//}

//func ctrXOR(block cipher.Block, iv, src, dst []byte) {
//	stream := cipher.NewCTR(block, iv)
//	stream.XORKeyStream(dst, src)
//}

func GenerateRandomKey(size int) []byte {
	key := make([]byte, size)
	_, _ = rand.Read(key)
	return key
}
