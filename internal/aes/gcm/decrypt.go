package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
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
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
