package covert

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var sampleText string = `It was a bright cold day in April, and the clocks were striking thirteen. Winston Smith,
his chin nuzzled into his breast in an effort to escape the vile wind, slipped quickly through the glass doors of
Victory Mansions, though not quickly enough to prevent a swirl of gritty dust from entering along with him.

The hallway smelt of boiled cabbage and old rag mats. At one end of it a coloured poster, too large for indoor
display, had been tacked to the wall. It depicted simply an enormous face, more than a metre wide: the face of a
man of about forty-five, with a heavy black moustache and ruggedly handsome features. Winston made for the stairs.
It was no use trying the lift. Even at the best of times it was seldom working, and at present the electric current
was cut off during daylight hours. It was part of the economy drive in preparation for HateWeek. The flat was seven
flights up, and Winston, who was thirty-nine and had a varicose ulcer above his right ankle, went slowly, resting
several times on the way. On each landing, opposite the lift shaft, the poster with the enormous face gazed from the
wall. It was one of those pictures which are so contrived that the eyes follow you about when you move.

BIG BROTHER IS WATCHING YOU, the caption beneath it ran.
`

func Test_CovertValidE2E(t *testing.T) {
	tests := []struct {
		name          string
		npart         int
		secretKeyPair DataKeyPair
		decoyKeyPairs []DataKeyPair
	}{
		{
			name:  "valid-5parts-1long-0decoys",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte(sampleText),
				Passphrase: "12345abcdeFGHIJ",
			},
		},
		{
			name:  "valid-2parts-1short-0decoys",
			npart: 2,
			secretKeyPair: DataKeyPair{
				Message:    []byte("a short test sentence."),
				Passphrase: "12345abcdeFGHIJ",
			},
		},
		{
			name:  "valid-5parts-1short-1decoys",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte("a short test sentence."),
				Passphrase: "12345abcdeFGHIJ",
			},
			decoyKeyPairs: []DataKeyPair{
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
			},
		},
		{
			name:  "valid-5parts-1short-2decoys",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte("a short test sentence."),
				Passphrase: "12345abcdeFGHIJ",
			},
			decoyKeyPairs: []DataKeyPair{
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
			},
		},
		{
			name:  "invalid-1-short-6-decoys",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte("a short test sentence."),
				Passphrase: "12345abcdeFGHIJ",
			},
			decoyKeyPairs: []DataKeyPair{
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(tt.npart)

			fmt.Println("Testing encryption...")
			ciphertext, err := e.Encrypt(tt.secretKeyPair, tt.decoyKeyPairs)
			assert.NoError(t, err)
			assert.NotEmpty(t, ciphertext, "Empty ciphertext")

			// Check length of ciphertext equals at least = n * (biggest secret + nonce)
			//allParts := append(tt.decoyKeyPairs, tt.secretKeyPair)
			//totalSize := tt.numPart * (setPartitionSize(allParts) + 12)
			//assert.Len(t, ciphertext, totalSize) // Overhead of AES-GCM + Nonce (12bit)

			fmt.Println("Testing decryption...")
			d := New(tt.npart)
			cleartext, err := d.Decrypt(ciphertext, tt.secretKeyPair.Passphrase)
			assert.NoError(t, err)
			assert.Equal(t, tt.secretKeyPair.Message, cleartext, "Input Message and output Message are different")
		})
	}
}

func TestCovert_randomizePartitionOrder(t *testing.T) {
	c := &Covert{
		volumes: []DataKeyPair{
			{
				Message:    []byte("partition-1"),
				Passphrase: "secret-1",
			},
			{
				Message:    []byte("partition-2"),
				Passphrase: "secret-2",
			},
			{
				Message:    []byte("partition-3"),
				Passphrase: "secret-3",
			},
			{
				Message:    []byte("partition-4"),
				Passphrase: "secret-4",
			},
			{
				Message:    []byte("partition-5"),
				Passphrase: "secret-5",
			},
		},
	}

	c.randomizePartitionOrder()
	if c.volumes[0].Passphrase == "secret-1" &&
		c.volumes[1].Passphrase == "secret-2" &&
		c.volumes[2].Passphrase == "secret-3" &&
		c.volumes[3].Passphrase == "secret-4" &&
		c.volumes[4].Passphrase == "secret-5" {
			t.Error("Partition order is the same")
	}

	c.randomizePartitionOrder()
	if c.volumes[0].Passphrase == "secret-1" &&
		c.volumes[1].Passphrase == "secret-2" &&
		c.volumes[2].Passphrase == "secret-3" &&
		c.volumes[3].Passphrase == "secret-4" &&
		c.volumes[4].Passphrase == "secret-5" {
		t.Error("Partition order is the same")
	}
}