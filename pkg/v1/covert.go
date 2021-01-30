package covert

import (
	"github.com/crashdump/covert/internal/rand"
	mrand "math/rand"
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

func (c *Covert) randomizePartitionOrder()  {
	// We use a cryptographically secure RNG to randomize the slice, otherwise:
	// 1. we would get the same sequence of pseudo-random numbers each time we run the program, or
	// 2. an attacker could use the file creation date/time to predict the ordering.
	r := mrand.New(rand.NewCryptoSource()) // TODO: Validate if implementation is right, linter is complaining.
	r.Shuffle(len(c.volumes), func(i, j int) {
		c.volumes[i], c.volumes[j] = c.volumes[j], c.volumes[i]
	})
}