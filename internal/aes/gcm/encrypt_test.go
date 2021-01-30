package aesgcm

import (
	"github.com/crashdump/covert/pkg/v1"
	"github.com/stretchr/testify/assert"
	"testing"
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

func Test_CovertValidEncryption(t *testing.T) {
	tests := []struct {
		name          string
		npart         int
		secretKeyPair covert.DataKeyPair
		decoyKeyPairs []covert.DataKeyPair
	}{
		{
			name:  "valid-1small-payload-1large-decoy",
			npart: 5,
			secretKeyPair: covert.DataKeyPair{
				Message:    []byte("abcde"),
				Passphrase: "82Cx-3970U2863_4d1384Be76a857e4B364",
			},
			decoyKeyPairs: []covert.DataKeyPair{
				{
					Message:    []byte(sampleText),
					Passphrase: "66906b68-4396-4d67-9117-ca72cd78bf40",
				},
			},
		},
		{
			name:  "valid-1-large-payload-1-small-decoy",
			npart: 5,
			secretKeyPair: covert.DataKeyPair{
				Message:    []byte(sampleText),
				Passphrase: "862f9d3ff5514a96-a2ff1be6277e06d6",
			},
			decoyKeyPairs: []covert.DataKeyPair{
				{
					Message:    []byte("abcde"),
					Passphrase: "b5bc17743c3-ba2a-e1f9b252af25",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := covert.New(5)
			ciphertext, err := e.Encrypt(tt.secretKeyPair, tt.decoyKeyPairs)
			assert.NoError(t, err)
			assert.NotEmpty(t, ciphertext)
		})
	}
}

func Test_CovertInvalidEncryption(t *testing.T) {
	tests := []struct {
		name          string
		npart         int
		secretKeyPair covert.DataKeyPair
		decoyKeyPairs []covert.DataKeyPair
	}{

		{
			name:  "invalid-no-passphrase",
			npart: 5,
			secretKeyPair: covert.DataKeyPair{
				Message:    []byte(sampleText),
				Passphrase: "",
			},
		},
		{
			name:  "invalid-no-content",
			npart: 5,
			secretKeyPair: covert.DataKeyPair{
				Message:    []byte(""),
				Passphrase: "82Cx-3970U2863_4d1384Be76a857e4B364",
			},
		},
		{
			name:  "invalid-no-data-or-content",
			npart: 5,
			secretKeyPair: covert.DataKeyPair{
				Message:    []byte(""),
				Passphrase: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := covert.New(5)
			ciphertext, err := e.Encrypt(tt.secretKeyPair, tt.decoyKeyPairs)
			assert.Error(t, err)
			assert.Empty(t, ciphertext)
		})
	}
}
