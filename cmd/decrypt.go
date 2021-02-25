package main

import (
	"errors"
	"flag"
	"fmt"
	covert "github.com/crashdump/covert/pkg/v1"
	"io/ioutil"
	"os"
)

type cmdDecrypt struct {
	fs         *flag.FlagSet
	fileIn     string
	fileOut    string
	passphrase string
}

func NewDecryptCmd() *cmdDecrypt {
	cd := &cmdDecrypt{
		fs: flag.NewFlagSet("decrypt", flag.ExitOnError),
	}
	cd.fs.StringVar(&cd.fileIn, "input", "", "file to encrypt (cleartext)")
	cd.fs.StringVar(&cd.fileOut, "output", "", "file output (encrypted)")

	return cd
}

func (g *cmdDecrypt) Name() string {
	return g.fs.Name()
}

func (g *cmdDecrypt) Init(args []string) error {
	return g.fs.Parse(args)
}

func (g *cmdDecrypt) Validate() error {
	if g.fileIn == "" {
		g.fs.PrintDefaults()
		return errors.New("you must specify the ciphered input file")
	}
	if g.fileOut == "" {
		g.fs.PrintDefaults()
		return errors.New("you must specify the cleartext file destination")
	}
	return nil
}

func (g *cmdDecrypt) Run() error {
	ciphertext, err := ioutil.ReadFile(g.fileIn)
	if err != nil {
		panic(err.Error())
	}

	// Required for UT
	if g.passphrase == "" {
		g.passphrase, err = readPassword(g.fileIn)
		if err != nil {
			return err
		}
	}

	f, err := os.Create(g.fileOut)
	if err != nil {
		panic(err.Error())
	}
	defer f.Close()

	d := covert.New(3)
	cleartext, err := d.Decrypt(ciphertext, g.passphrase)
	if err != nil {
		panic(err.Error())
	}

	_, err = f.Write(cleartext)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("success.")

	return nil
}
