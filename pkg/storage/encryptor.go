package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const streamChunkSize = 32 << 20

type Encryptor interface {
	EncryptStream(w io.Writer) (io.Writer, error)
	DecryptStream(r io.Reader) (io.Reader, error)
	EncryptBytes(plaintext []byte) ([]byte, error)
	NewDecryptWriter(w io.Writer) DecryptWriter
}

type DecryptWriter interface {
	io.Writer
	Close() error
}

type aesEncryptor struct {
	block cipher.Block
}

func NewDefaultEncryptor(key []byte) (Encryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}
	return &aesEncryptor{block: block}, nil
}

func (e aesEncryptor) EncryptStream(w io.Writer) (io.Writer, error) {
	iv := GenerateRandomKey(e.block.BlockSize())
	if _, err := w.Write(iv); err != nil {
		return nil, fmt.Errorf("failed to write iv: %w", err)
	}
	stream := cipher.NewCTR(e.block, iv)
	return &chunkedStreamWriter{stream: stream, w: w}, nil //nolint:exhaustruct_v5 // it's buf
}

func (e aesEncryptor) DecryptStream(r io.Reader) (io.Reader, error) {
	iv := make([]byte, e.block.BlockSize())
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, fmt.Errorf("failed to read iv: %w", err)
	}
	stream := cipher.NewCTR(e.block, iv)
	return &cipher.StreamReader{S: stream, R: r}, nil
}

func (e aesEncryptor) EncryptBytes(plaintext []byte) ([]byte, error) {
	blockSize := e.block.BlockSize()
	out := make([]byte, blockSize+len(plaintext))
	if _, err := io.ReadFull(rand.Reader, out[:blockSize]); err != nil {
		return nil, fmt.Errorf("failed to generate random IV: %w", err)
	}
	stream := cipher.NewCTR(e.block, out[:blockSize])
	stream.XORKeyStream(out[blockSize:], plaintext)
	return out, nil
}

func (e aesEncryptor) NewDecryptWriter(w io.Writer) DecryptWriter {
	return &decryptStreamWriter{block: e.block, w: w} //nolint:exhaustruct_v5 // skipping manual init of buf
}

type chunkedStreamWriter struct {
	stream cipher.Stream
	w      io.Writer
	buf    [streamChunkSize]byte
}

func (c *chunkedStreamWriter) Write(src []byte) (int, error) {
	total := len(src)
	for len(src) > 0 {
		chunk := min(len(src), len(c.buf))
		c.stream.XORKeyStream(c.buf[:chunk], src[:chunk])
		nw, err := c.w.Write(c.buf[:chunk])
		if err != nil {
			return total - len(src) + nw, fmt.Errorf("failed to write encrypted data: %w", err)
		}
		if nw != chunk {
			return total - len(src) + nw, io.ErrShortWrite
		}
		src = src[chunk:]
	}
	return total, nil
}

type decryptStreamWriter struct {
	block  cipher.Block
	stream cipher.Stream
	w      io.Writer
	iv     [aes.BlockSize]byte
	ivLen  int
	buf    [streamChunkSize]byte
}

func (d *decryptStreamWriter) Write(p []byte) (int, error) {
	total := len(p)
	blockSize := d.block.BlockSize()

	if d.ivLen < blockSize {
		n := copy(d.iv[d.ivLen:blockSize], p)
		d.ivLen += n
		p = p[n:]
		if d.ivLen == blockSize {
			d.stream = cipher.NewCTR(d.block, d.iv[:blockSize])
		}
	}

	for len(p) > 0 {
		chunk := min(len(p), len(d.buf))
		d.stream.XORKeyStream(d.buf[:chunk], p[:chunk])
		nw, err := d.w.Write(d.buf[:chunk])
		if err != nil {
			return total - len(p) + nw, fmt.Errorf("failed to write decrypted data: %w", err)
		}
		if nw != chunk {
			return total - len(p) + nw, io.ErrShortWrite
		}
		p = p[chunk:]
	}

	return total, nil
}

func (d *decryptStreamWriter) Close() error {
	if d.ivLen < d.block.BlockSize() {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func GenerateRandomKey(size int) []byte {
	key := make([]byte, size)
	_, _ = rand.Read(key)
	return key
}
