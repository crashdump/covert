package covert

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/crashdump/covert/internal/pkcs7"
	"golang.org/x/crypto/scrypt"
)

//
func (c *Covert) Decrypt(ciphertext []byte, passphrase string) ([]byte, error) {
	if len(ciphertext) == 0 || len(passphrase) == 0 {
		return nil, errors.New("ciphertext and Passphrase must be != 0")
	}

	vsize := len(ciphertext)
	psize := vsize / c.numPart
	if r := vsize % c.numPart; r != 0 {
		err := fmt.Sprintf("incorrect volume size/partition ratio (%d bytes / %d partitions = %d bytes !)", vsize, c.numPart, r)
		return nil, errors.New(err)
	}

	for i := 0; i < vsize; i += psize {
		cleartext, err := decrypt(ciphertext[i:i+psize], passphrase)
		if err != nil {
			continue
		}

		cleartext, err = pkcs7.Unpad(cleartext, BLOCKSIZE)
		if err != nil {
			return nil, err
		}

		return cleartext, nil
	}

	return nil, errors.New("no partitions matching this key were found")
}

func decrypt(ciphertext []byte, passphrase string) ([]byte, error) {
	fmt.Printf("cyphertext is %d bytes: %x\n", len(ciphertext), ciphertext)

	key, err := hash(passphrase)
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
	if len(ciphertext) % aes.BlockSize != 0 {
		err := fmt.Sprintf("ciphertext is not a multiple of the block size (%d mod %d != 0)", len(ciphertext), aes.BlockSize)
		return nil, errors.New(err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

func hash(key string) ([]byte, error) {
	// Recommended parameters for scrypt for file encryption are N=1048576, r=8, p=1 (1Gb)
	// The key should be 32 bits with AES-256
	return scrypt.Key([]byte(key), []byte("1234"), 1048576, 8, 1, 32) // TODO: Change the salt
}