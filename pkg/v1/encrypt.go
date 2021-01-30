package covert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/crashdump/covert/internal/pkcs7"
	"io"
)


const BLOCKSIZE = 64

func (c *Covert) Encrypt(secrets DataKeyPair, decoys []DataKeyPair) ([]byte, error) {
	c.volumes = append(c.volumes, secrets)
	c.volumes = append(c.volumes, decoys...)
	var err error

	// Validate input parameters are acceptable and find the size of the largest partition.
	for _, dkp := range c.volumes {
		messageLength := len(dkp.Message)
		if messageLength == 0 || len(dkp.Passphrase) == 0 {
			return nil, errors.New("'cleartext' and 'Passphrase' length must be > 0")
		}
		if messageLength > c.partSize {
			c.partSize = messageLength
		}
	}

	fmt.Printf("partition size will be at least %d\n", c.partSize)

	// Calculate how many garbage partitions we need to create and create them
	c.numGP = c.numPart - len(c.volumes)
	if c.numGP < 0 {
		return nil, errors.New("there are more data/key pair than total partitions")
	}
	for i := 0; i < c.numGP; i++ {
		passphrase := make([]byte, 32)
		_, err := rand.Read(passphrase) // Generate random passphrase
		if err != nil {
			return nil, err
		}

		gv := DataKeyPair{
			Message:    []byte{0},
			Passphrase: string(passphrase),
		}
		c.volumes = append(c.volumes, gv)
	}

	// Pad the data
	for i, dkp := range c.volumes {
		fmt.Printf("padding partition %d/%d\n", i +1, c.numPart)

		c.volumes[i].Message, err = pkcs7.Pad(dkp.Message, BLOCKSIZE) //c.partSize)
		if err != nil {
			return nil, err
		}
	}

	// Randomise partition order
	c.randomizePartitionOrder()
	fmt.Printf("randomizing partition order\n")

	// And finally, encrypt and concatenate them
	var cipheredVolume []byte
	for i, dkp := range c.volumes {
		fmt.Printf("encrypting partition %d/%d\n", i+1, c.numPart)

		ciphertext, err := encrypt(dkp.Message, dkp.Passphrase)
		if err != nil {
			return nil, err
		}

		cipheredVolume = append(cipheredVolume, ciphertext...)
	}

	return cipheredVolume, nil
}


func encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	key, err := hash(passphrase)
	if err != nil {
		return nil, err
	}

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block (https://tools.ietf.org/html/rfc5246#section-6.2.3.2)
	if len(plaintext) % aes.BlockSize != 0 {
		err := fmt.Sprintf("plaintext is not a multiple of the block size (%d / %d != 0)", len(plaintext), aes.BlockSize)
		return nil, errors.New(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil { panic(err) }

	// The IV needs to be unique, but not secret. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize + len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil { panic(err) }

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	fmt.Printf("cyphertext is %d bytes: %x\n", len(ciphertext), ciphertext)

	return ciphertext, nil
}