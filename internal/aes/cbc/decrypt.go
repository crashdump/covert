package aescbc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/crashdump/covert/internal/scrypt"
)

func Decrypt(ciphertext []byte, passphrase string) ([]byte, error) {
	fmt.Printf("cyphertext is %d bytes: %x\n", len(ciphertext), ciphertext)

	key, err := scrypt.Hash(passphrase)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		err := fmt.Sprintf("ciphertext is not a multiple of the block size (%d mod %d != 0)", len(ciphertext), aes.BlockSize)
		return nil, errors.New(err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}
