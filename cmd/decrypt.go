package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	covert "github.com/crashdump/covert/pkg/v1"
	"io/ioutil"
	"os"
)

type cmdDecrypt struct {
	fs *flag.FlagSet
	//name    string
	fileIn  string
	fileOut string
	key     string
}

func NewDecryptCmd() *cmdDecrypt {
	cd := &cmdDecrypt{
		fs: flag.NewFlagSet("decrypt", flag.ExitOnError),
	}
	cd.fs.StringVar(&cd.fileIn, "input", "", "file to encrypt (cleartext)")
	cd.fs.StringVar(&cd.fileOut, "output", "", "file output (encrypted)")

	// TODO: Use stdin to ask for the key instead of the command line (insecure / shell history)
	cd.fs.StringVar(&cd.key, "key", "", "secret key to decrypt the data")

	return cd
}

func (g *cmdDecrypt) Name() string {
	return g.fs.Name()
}

func (g *cmdDecrypt) Init(args []string) error {
	return g.fs.Parse(args)
}

func (g *cmdDecrypt) Validate() error {
	if g.fileIn == "" || g.key == "" {
		g.fs.PrintDefaults()
		return errors.New("you must specify the input file and a key")
	}
	if g.fileOut == "" {
		g.fs.PrintDefaults()
		return errors.New("you must specify the cleartext output file")
	}
	return nil
}

func (g *cmdDecrypt) Run() error {
	ciphertext, err := ioutil.ReadFile(g.fileIn)
	if err != nil {
		panic(err.Error())
	}

	f, err := os.Create(g.fileOut)
	if err != nil {
		panic(err.Error())
	}
	defer f.Close()

	e := covert.New(5)
	cleartext, err := e.Decrypt(ciphertext, g.key)
	if err != nil {
		panic(err.Error())
	}

	f.Write(cleartext)

	// TODO: Delete this debugging output
	fmt.Printf("--- DECRYPTION ---\n ciphertext: %s\n  cleartext: %s\n", base64.StdEncoding.EncodeToString(ciphertext), cleartext)

	return nil
}
