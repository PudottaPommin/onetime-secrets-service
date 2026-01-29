package storage

import (
	"encoding/gob"
	"io"
)

type Encoder interface {
	EncodeStream(w io.Writer, data any) error
	DecodeStream(r io.Reader, dst any) error
	//Encode(data any) ([]byte, error)
	//Decode(src []byte, dst any) error
}

type GobEncoder struct{}

func (e GobEncoder) EncodeStream(w io.Writer, data any) error {
	return gob.NewEncoder(w).Encode(data)
}

func (e GobEncoder) DecodeStream(r io.Reader, dst any) error {
	return gob.NewDecoder(r).Decode(dst)
}

//func (e GobEncoder) Encode(data any) ([]byte, error) {
//	b := bytebufferpool.Get()
//	defer bytebufferpool.Put(b)
//	if err := gob.NewEncoder(b).Encode(data); err != nil {
//		return nil, err
//	}
//	return b.Bytes(), nil
//}
//
//func (e GobEncoder) Decode(src []byte, dst any) error {
//	return e.DecodeStream(bytes.NewReader(src), dst)
//}
