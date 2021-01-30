package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/crashdump/covert/internal/scrypt"
	"io"
)

func Encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	key, err := scrypt.Hash(passphrase)
	if err != nil {
		return nil, err
	}

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block (https://tools.ietf.org/html/rfc5246#section-6.2.3.2)
	if len(plaintext)%aes.BlockSize != 0 {
		err := fmt.Sprintf("plaintext is not a multiple of the block size (%d / %d != 0)", len(plaintext), aes.BlockSize)
		return nil, errors.New(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// NewGCM returns the given 128-bit, block cipher wrapped in
	// Galois Counter Mode with the standard nonce length.
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// We add the nonce as a prefix to the encrypted data (first argument)
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)

	fmt.Printf("cyphertext is %d bytes: %x\n", len(ciphertext), ciphertext)

	return ciphertext, nil
}
