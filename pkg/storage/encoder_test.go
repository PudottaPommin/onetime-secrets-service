package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/bytebufferpool"
)

func TestGobEncoder(t *testing.T) {
	type testStruct struct {
		B []byte
		S string
		I int
	}
	tstruct := testStruct{
		B: []byte("rand"),
		S: "test",
		I: 1,
	}

	encoder := GobEncoder{}
	encoded, err := encoder.Encode(tstruct)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)

	decoded := testStruct{}
	assert.NoError(t, encoder.Decode(encoded, &decoded))
	assert.Equal(t, tstruct, decoded)
	assert.Equal(t, tstruct.B, decoded.B)
}

func TestGobEncoderStream(t *testing.T) {
	type testStruct struct {
		B []byte
		S string
		I int
	}
	tstruct := testStruct{
		B: []byte("rand"),
		S: "test",
		I: 1,
	}

	encoder := GobEncoder{}
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	err := encoder.EncodeStream(buf, tstruct)
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.Bytes())

	decoded := testStruct{}
	assert.NoError(t, encoder.DecodeStream(bytes.NewReader(buf.Bytes()), &decoded))
	assert.Equal(t, tstruct, decoded)
}
