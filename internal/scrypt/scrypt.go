package scrypt

import (
	"golang.org/x/crypto/scrypt"
)

func Hash(key string) ([]byte, error) {
	// Recommended parameters for scrypt for file encryption are N=1048576, r=8, p=1 (1Gb)
	// The key should be 32 bits with AES-256
	return scrypt.Key([]byte(key), []byte{7, 77, 29, 46, 14, 24, 38, 5}, 1048576, 8, 1, 32)
}
