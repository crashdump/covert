package main

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func Test_CovertEncryptionDecryption(t *testing.T) {
	tests := []struct {
		name               string
		cleartextContent   string
		cleartextFilename  fileInputArrayFlag
		cyphertextFilename string
		passphrase         string
	}{
		{
			name:               "valid-short-sentence",
			cleartextContent:   "a short sentence.",
			cleartextFilename:  fileInputArrayFlag{"/tmp/test-1.txt"},
			cyphertextFilename: "/tmp/test-1.bin",
			passphrase:         "e.X3d545bAa794a099e4C-3a181V326ba0",
		},
		{
			name:               "valid-long-sentence",
			cleartextContent:   "a much longer sentence, composed of many words, of which the total size in bites will be longer than an AES block. This should validate that larger payload can successfully be handled.",
			cleartextFilename:  fileInputArrayFlag{"/tmp/test-2.txt"},
			cyphertextFilename: "/tmp/test-2.bin",
			passphrase:         "fC32%301-8cU544eababc1b783X63_2dKL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write test data to the cleartext file
			f, err := os.Create(tt.cleartextFilename[0])
			if err != nil {
				panic(err.Error())
			}
			defer f.Close()
			f.Write([]byte(tt.cleartextContent))

			// Encrypt
			e := NewEncryptCmd()
			e.fileIn = tt.cleartextFilename
			e.fileOut = tt.cyphertextFilename
			e.passphrase = tt.passphrase
			e.Run()

			// Ensure output file has been created
			assert.FileExists(t, tt.cyphertextFilename, "Output ciphered file does not exist")

			// Remove original cleartext file
			err = os.Remove(tt.cleartextFilename[0])
			assert.NoError(t, err)

			// Ensure output file does not exist
			assert.NoFileExists(t, tt.cleartextFilename[0])

			// Decrypt ciphered file
			d := NewDecryptCmd()
			d.fileIn = tt.cyphertextFilename
			d.fileOut = tt.cleartextFilename[0]
			d.passphrase = tt.passphrase
			err = d.Run()
			if err != nil {
				log.Fatal(err)
			}

			// Read the cleartext file and ensure it matches the original input
			content, err := ioutil.ReadFile(tt.cleartextFilename[0])
			if err != nil {
				log.Fatal(err)
			}
			assert.Equal(t, tt.cleartextContent, string(content))
		})
	}
}

// TODO: Re-enable this test when I figure out how to mock the secure stdin.
//func Test_CovertMainEncrypt(t *testing.T) {
//	tests := []struct {
//		name               string
//		wantErr            bool
//		cleartextContent   string
//		cleartextFilename  string
//		cyphertextFilename string
//		passphrase         string
//	}{
//		{
//			name:               "invalid-passphrase-too-short",
//			wantErr:            true,
//			cleartextContent:   "a short sentence.",
//			cleartextFilename:  "/tmp/test-10.txt",
//			cyphertextFilename: "/tmp/test-10.bin",
//			passphrase:         "12345",
//		},
//		{
//			name:               "valid-passphrase",
//			wantErr:            false,
//			cleartextContent:   "a short sentence.",
//			cleartextFilename:  "/tmp/test-11.txt",
//			cyphertextFilename: "/tmp/test-11.bin",
//			passphrase:         "3fecc039-f258-49ee-9f49-5e88ddf60e68",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			// Write test data to the cleartext file
//			f, err := os.Create(tt.cleartextFilename)
//			if err != nil {
//				panic(err.Error())
//			}
//			defer f.Close()
//			f.Write([]byte(tt.cleartextContent))
//
//			// Ensure there is not output file
//			_ = os.Remove(tt.cyphertextFilename)
//
//			err = root([]string{"encrypt", "-input", tt.cleartextFilename, "-output", tt.cyphertextFilename})
//
//			if tt.wantErr {
//				assert.Error(t, err)
//				// Ensure output file does not exist
//				assert.NoFileExists(t, tt.cyphertextFilename, "We should not have an output file since the test should have failed")
//			} else {
//				assert.NoError(t, err)
//				assert.FileExists(t, tt.cyphertextFilename)
//			}
//		})
//	}
//}
