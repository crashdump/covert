package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/crashdump/covert/pkg/v1"
)

type cmdEncrypt struct {
	fs *flag.FlagSet
	//name    string
	nPart   int
	fileIn  string
	fileOut string
	key     string
}

func NewEncryptCmd() *cmdEncrypt {
	ce := &cmdEncrypt{
		fs: flag.NewFlagSet("encrypt", flag.ExitOnError),
	}
	ce.fs.IntVar(&ce.nPart, "npart", 5, "Number of partitions")

	ce.fs.StringVar(&ce.fileIn, "input", "", "file to encrypt (cleartext)")
	ce.fs.StringVar(&ce.fileOut, "output", "", "file output (encrypted)")

	// TODO: Use stdin to ask for the key instead of the command line (insecure / shell history)
	ce.fs.StringVar(&ce.key, "key", "", "secret key to encrypt the file")

	return ce
}

func (g *cmdEncrypt) Name() string {
	return g.fs.Name()
}

func (g *cmdEncrypt) Init(args []string) error {
	return g.fs.Parse(args)
}

func (g *cmdEncrypt) Validate() error {
	if g.fileIn == "" || g.key == "" {
		g.fs.PrintDefaults()
		return errors.New("you must specify at least one input (file + key) pair")
	}
	if g.fileOut == "" {
		g.fs.PrintDefaults()
		return errors.New("you must specify the cyphered output file")
	}
	if len(g.key) <= 10 {
		return errors.New("the secret key must be at least 10 characters")
	}
	return nil
}

func (g *cmdEncrypt) Run() error {
	cleartext, err := ioutil.ReadFile(g.fileIn)
	if err != nil {
		panic(err.Error())
	}

	f, err := os.Create(g.fileOut)
	if err != nil {
		panic(err.Error())
	}
	defer f.Close()

	d := covert.New(5)
	ciphertext, err := d.Encrypt(
		covert.DataKeyPair{
			Message:    cleartext,
			Passphrase: g.key,
		},
		[]covert.DataKeyPair{
			{
				Message: []byte(""),
			},
		})
	if err != nil {
		panic(err.Error())
	}

	f.Write(ciphertext)

	// TODO: Delete this debugging output
	fmt.Printf("--- ENCRYPTION ---\n  cleartext: %s\n ciphertext: %s\n", cleartext, base64.StdEncoding.EncodeToString(ciphertext))

	return nil
}
