package covert

import (
	"crypto/rand"
	"errors"
	"fmt"
	aesgcm "github.com/crashdump/covert/internal/aes/gcm"
	mrand "math/rand"

	"github.com/crashdump/covert/internal/pkcs7"
	"github.com/crashdump/covert/internal/srand"
)

type Covert struct {
	numPart  int
	partSize int
	numGP    int
	volumes  []DataKeyPair
}

type DataKeyPair struct {
	Message    []byte
	Passphrase string
}

func New(npart int) *Covert {
	if npart != 0 {
		return &Covert{numPart: npart}
	}
	return &Covert{numPart: 3}
}

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
		c.volumes[i].Message, err = pkcs7.Pad(dkp.Message, BLOCKSIZE) //c.partSize)
		if err != nil {
			return nil, err
		}
	}

	// Randomise partition order
	c.randomizePartitionOrder()
	fmt.Printf("randomizing partition order\n")

	// And finally, encryptAES256CBC and concatenate them
	var cipheredVolume []byte
	for i, dkp := range c.volumes {
		fmt.Printf("encrypting partition %d/%d\n", i+1, c.numPart)

		ciphertext, err := aesgcm.Encrypt(dkp.Message, dkp.Passphrase)
		if err != nil {
			return nil, err
		}

		cipheredVolume = append(cipheredVolume, ciphertext...)
	}

	return cipheredVolume, nil
}

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
		cleartext, err := aesgcm.Decrypt(ciphertext[i:i+psize], passphrase)
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

func (c *Covert) randomizePartitionOrder() {
	// We use a cryptographically secure RNG to randomize the slice, otherwise:
	// 1. we would get the same sequence of pseudo-random numbers each time we run the program, or
	// 2. an attacker could use the file creation date/time to predict the ordering.
	r := mrand.New(srand.NewCryptoSource()) // TODO: Validate if implementation is right, linter is complaining.
	r.Shuffle(len(c.volumes), func(i, j int) {
		c.volumes[i], c.volumes[j] = c.volumes[j], c.volumes[i]
	})
}