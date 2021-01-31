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
		name       string
		npart      int
		partitions []DataKeyPair
		wantErr    bool
	}{
		{
			name:  "invalid-2partitions-1long",
			npart: 2,
			partitions: []DataKeyPair{
				{
					Message:    []byte(sampleText),
					Passphrase: "!@WtpJeo95uIHwKfyU(8fdOIe",
				},
			},
			wantErr: true,
		},
		{
			name:  "valid-3partitions-1long",
			npart: 3,
			partitions: []DataKeyPair{
				{
					Message:    []byte(sampleText),
					Passphrase: "qKO329wt|i5w8p3PywtIO7iq",
				},
			},
			wantErr: false,
		},
		{
			name:  "valid-3partitions-1short",
			npart: 3,
			partitions: []DataKeyPair{
				{
					Message:    []byte("a short test sentence."),
					Passphrase: "12345aJOI45e)p0i'GHIJ",
				},
			},
			wantErr: false,
		},
		{
			name:  "valid-5partitions-1short-1decoys",
			npart: 5,
			partitions: []DataKeyPair{
				{
					Message:    []byte("a short test sentence."),
					Passphrase: "12345abcdeFGHIJ",
				},
				{
					Message:    []byte("a decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
			},
			wantErr: false,
		},
		{
			name:  "valid-10partitions",
			npart: 10,
			partitions: []DataKeyPair{
				{
					Message:    []byte("a short test sentence."),
					Passphrase: "12345abcdeFGHIJ",
				},
				{
					Message:    []byte("a number."),
					Passphrase: "uhFh;oj(*U0iL0pig",
				},
				{
					Message:    []byte("another decoy."),
					Passphrase: "uhFheuKLfdi32d89t4.y",
				},
			},
			wantErr: false,
		},
		{
			name:  "invalid-5partitions-6decoys",
			npart: 5,
			partitions: []DataKeyPair{
				{
					Message:    []byte("a short test sentence."),
					Passphrase: "aD;opw7643FWEw3-pq3oi",
				},
				{
					Message:    []byte("the first decoy."),
					Passphrase: "8u9fdio8u89d8o0uoiu",
				},
				{
					Message:    []byte("the second decoy."),
					Passphrase: "09ifdi32dp;lokh80",
				},
				{
					Message:    []byte("the third decoy."),
					Passphrase: "435ertyLfdi32d7r65er",
				},
				{
					Message:    []byte("the fourth decoy."),
					Passphrase: "jmhnbfdi32d809o8iu",
				},
				{
					Message:    []byte("the fifth decoy."),
					Passphrase: "09o8iud89lk,jmnb",
				},
				{
					Message:    []byte("the seventh decoy."),
					Passphrase: "09=i8uyNdi32d89tuOWwKlKop",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(tt.npart)

			fmt.Println("Testing encryption...")
			ciphertext, err := e.Encrypt(tt.partitions)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, ciphertext)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, ciphertext, "Empty ciphertext")

			fmt.Println("Testing decryption...")
			d := New(tt.npart)

			for _, partition := range tt.partitions {
				cleartext, err := d.Decrypt(ciphertext, partition.Passphrase)
				assert.NoError(t, err)
				assert.Equal(t, partition.Message, cleartext, "Input Message and output Message are different")
			}
		})
	}
}

func TestCovert_randomizePartitionOrder(t *testing.T) {
	c := &Covert{
		volumes: []DataKeyPair{
			{
				Message:    []byte("partitions-1"),
				Passphrase: "secret-1",
			},
			{
				Message:    []byte("partitions-2"),
				Passphrase: "secret-2",
			},
			{
				Message:    []byte("partitions-3"),
				Passphrase: "secret-3",
			},
			{
				Message:    []byte("partitions-4"),
				Passphrase: "secret-4",
			},
			{
				Message:    []byte("partitions-5"),
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
