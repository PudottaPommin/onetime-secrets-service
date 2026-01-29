package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

	encoder := GobEncoder[testStruct]{}
	encoded, err := encoder.Encode(tstruct)
	assert.NoError(t, err)
	assert.NotEmpty(t, encoded)

	decoded := testStruct{}
	assert.NoError(t, encoder.Decode(encoded, &decoded))
	assert.Equal(t, tstruct, decoded)
	assert.Equal(t, tstruct.B, decoded.B)
}
