package covert

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_CovertValidEncryption(t *testing.T) {
	tests := []struct {
		name          string
		npart         int
		secretKeyPair DataKeyPair
		decoyKeyPairs []DataKeyPair
	}{
		{
			name:  "valid-1small-payload-1large-decoy",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte("abcde"),
				Passphrase: "82Cx-3970U2863_4d1384Be76a857e4B364",
			},
			decoyKeyPairs: []DataKeyPair{
				{
					Message:    []byte(sampleText),
					Passphrase: "66906b68-4396-4d67-9117-ca72cd78bf40",
				},
			},
		},
		{
			name:  "valid-1-large-payload-1-small-decoy",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte(sampleText),
				Passphrase: "862f9d3ff5514a96-a2ff1be6277e06d6",
			},
			decoyKeyPairs: []DataKeyPair{
				{
					Message:    []byte("abcde"),
					Passphrase: "b5bc17743c3-ba2a-e1f9b252af25",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(5)
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
		secretKeyPair DataKeyPair
		decoyKeyPairs []DataKeyPair
	}{

		{
			name:  "invalid-no-passphrase",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte(sampleText),
				Passphrase: "",
			},
		},
		{
			name:  "invalid-no-content",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte(""),
				Passphrase: "82Cx-3970U2863_4d1384Be76a857e4B364",
			},
		},
		{
			name:  "invalid-no-data-or-content",
			npart: 5,
			secretKeyPair: DataKeyPair{
				Message:    []byte(""),
				Passphrase: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(5)
			ciphertext, err := e.Encrypt(tt.secretKeyPair, tt.decoyKeyPairs)
			assert.Error(t, err)
			assert.Empty(t, ciphertext)
		})
	}
}