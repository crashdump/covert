package pkcs7

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Pad(t *testing.T) {
	tests := []struct {
		name      string
		byteIn    []byte
		byteWant  []byte
		blockSize int
	}{
		{
			name:      "valid-long",
			byteIn:    []byte{0x1, 0x2, 0x3, 0x4, 0x5},
			byteWant:  []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb},
			blockSize: 16,
		},
		{
			name:      "valid-short",
			byteIn:    []byte{1},
			byteWant:  []byte{0x1, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7},
			blockSize: 8,
		},
		{
			name:      "valid-short-block",
			byteIn:    []byte{0x1},
			byteWant:  []byte{0x1, 0x1},
			blockSize: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Pad(tt.byteIn, tt.blockSize)
			assert.NoError(t, err)

			assert.Equal(t, tt.byteWant, got)
		})
	}
}

func Test_Unpad(t *testing.T) {
	tests := []struct {
		name     string
		byteIn   []byte
		byteWant []byte
		blockSize int
	}{
		{
			name:     "valid-1",
			byteIn:   []byte{45, 56, 67, 78, 57, 4, 4, 4, 4},
			byteWant: []byte{45, 56, 67, 78, 57},
			blockSize: 8,

		},
		{
			name:     "valid-2",
			byteIn:   []byte{76, 65, 68, 78, 43, 4, 4, 66, 4, 4, 4},
			byteWant: []byte{76, 65, 68, 78, 43, 4, 4, 66},
			blockSize: 4,
		},
		{
			name:     "valid-3",
			byteIn:   []byte{86, 4},
			byteWant: []byte{86},
			blockSize: 16,
		},
		{
			name:     "valid-4",
			byteIn:   []byte{4},
			byteWant: []byte{},
			blockSize: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := Unpad(tt.byteIn, tt.blockSize)
			assert.Equal(t, tt.byteWant, got)
		})
	}
}

func Test_PadE2E(t *testing.T) {
	tests := []struct {
		name      string
		byteIn    []byte
		blockSize int
	}{
		{
			name:      "valid-string",
			byteIn:    []byte("Test data which has absolutely no sense."),
			blockSize: 90,
		},
		{
			name:      "valid-int",
			byteIn:    []byte{76, 65, 68, 78, 43, 4, 4, 66},
			blockSize: 20,
		},
		{
			name:      "valid-1-byte",
			byteIn:    []byte{4},
			blockSize: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded, err := Pad(tt.byteIn, tt.blockSize)
			assert.NoError(t, err)

			out, err := Unpad(padded, 8)
			assert.NoError(t, err)

			assert.Equal(t, tt.byteIn, out)
		})
	}
}