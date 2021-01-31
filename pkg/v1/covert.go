package covert

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	aesgcm "github.com/crashdump/covert/internal/aes/gcm"
	mrand "math/rand"

	"github.com/crashdump/covert/internal/msg"
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
	return &Covert{numPart: npart}
}

func (c *Covert) Encrypt(partitions []DataKeyPair) ([]byte, error) {
	if c.numPart < 3 {
		return nil, msg.ErrCovertInvalidAmountPartition
	}

	c.volumes = partitions
	var err error

	// Validate input parameters are acceptable and find the size of the largest partitions.
	for _, dkp := range c.volumes {
		messageLength := len(dkp.Message)
		if len(dkp.Passphrase) == 0 {
			return nil, msg.ErrCovertInvalidLengthPassphrase
		}
		if messageLength == 0 {
			return nil, msg.ErrCovertInvalidLengthCleartext
		}

		if messageLength > c.partSize {
			// Looking for the next highest number divisible by 16 (block size)
			for i := messageLength; i%16 != 0; i++ {
				c.partSize = i + 1
			}
		}
	}
	fmt.Printf("partitions size is %d\n", c.partSize)

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
		c.volumes[i].Message, err = pkcs7.Pad(dkp.Message, c.partSize)
		if err != nil {
			return nil, err
		}
	}

	// Randomise partitions order
	c.randomizePartitionOrder()
	fmt.Printf(msg.InfoCovertPartitionRandomOrder)

	// And finally, encrypt each partitions with AES256-GCM and concatenate them into a volume
	var cipheredVolume []byte //nolint:prealloc
	for i, dkp := range c.volumes {
		fmt.Printf(msg.InfoCovertPartitionEncryption, i+1, c.numPart)

		ciphertext, err := aesgcm.Encrypt(dkp.Message, dkp.Passphrase)
		if err != nil {
			return nil, err
		}

		cipheredVolume = append(cipheredVolume, ciphertext...)
	}

	return cipheredVolume, nil
}

func (c *Covert) Decrypt(ciphertext []byte, passphrase string) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, msg.ErrCovertInvalidLengthPassphrase
	}
	if len(passphrase) == 0 {
		return nil, msg.ErrCovertInvalidLengthCleartext
	}

	vsize := len(ciphertext)
	psize := vsize / c.numPart
	if r := vsize % c.numPart; r != 0 {
		err := fmt.Sprintf("incorrect volume size/partitions ratio (%d bytes / %d partitions = %d bytes !)", vsize, c.numPart, r)
		return nil, errors.New(err)
	}

	for i := 0; i < vsize; i += psize {
		cleartext, err := aesgcm.Decrypt(ciphertext[i:i+psize], passphrase)
		if err != nil {
			continue
		}

		cleartext, err = pkcs7.Unpad(cleartext, aes.BlockSize)
		if err != nil {
			return nil, err
		}

		return cleartext, nil
	}

	return nil, msg.ErrCovertNoPartitionMacthKey
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
