package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func GenerateNewKey(len int) []byte {
	key := make([]byte, len)
	_, _ = rand.Read(key)
	return key
}

func Encrypt(msg, key []byte) ([]byte, error) {
	gcm, err := getGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	s := gcm.Seal(nonce, nonce, msg, nil)
	return s, nil
}

func Decrypt(msg, key []byte) (string, error) {
	gcm, err := getGCM(key)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := msg[:nonceSize], msg[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func getGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, err
}
