package srand

import (
	"crypto/rand"
	"encoding/binary"
)

type cryptoSource struct{}

func NewCryptoSource() cryptoSource {
	return cryptoSource{}
}

func (_ cryptoSource) Int63() int64 {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	// mask off sign bit to ensure positive number
	return int64(binary.LittleEndian.Uint64(b[:]) & (1<<63 - 1))
}

func (_ cryptoSource) Seed(_ int64) {}
