package aescbc

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
	if passphrase == "" {
		return nil, errors.New("you must provide a passphrase")
	}

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
		panic(err)
	}

	// The IV needs to be unique, but not secret. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	fmt.Printf("cyphertext is %d bytes: %x\n", len(ciphertext), ciphertext)

	return ciphertext, nil
}
