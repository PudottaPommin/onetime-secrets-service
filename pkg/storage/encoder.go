package storage

import (
	"bytes"
	"encoding/gob"

	"github.com/valyala/bytebufferpool"
)

type Encoder interface {
	Encode(data any) ([]byte, error)
	Decode(src []byte, dst any) error
}

type GobEncoder struct{}

func (e GobEncoder) Encode(data any) ([]byte, error) {
	b := bytebufferpool.Get()
	defer bytebufferpool.Put(b)
	if err := gob.NewEncoder(b).Encode(data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (e GobEncoder) Decode(src []byte, dst any) error {
	return gob.NewDecoder(bytes.NewReader(src)).Decode(dst)
}
