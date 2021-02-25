package main

import (
	"errors"
	"flag"
	"fmt"
	covert "github.com/crashdump/covert/pkg/v1"
	"io/ioutil"
	"os"
	"strings"
)

type cmdEncrypt struct {
	fs         *flag.FlagSet
	nPart      int
	fileIn     fileInputArrayFlag
	fileOut    string
	passphrase string
}

func NewEncryptCmd() *cmdEncrypt {
	ce := &cmdEncrypt{
		fs: flag.NewFlagSet("encrypt", flag.ExitOnError),
	}
	ce.fs.IntVar(&ce.nPart, "garbage-partitions", 1, "Number of garbage partitions")
	ce.fs.Var(&ce.fileIn, "input", "File(s) to encrypt, repeat as much as needed")
	ce.fs.StringVar(&ce.fileOut, "output", "", "file output (encrypted)")
	return ce
}

func (g *cmdEncrypt) Name() string {
	return g.fs.Name()
}

func (g *cmdEncrypt) Init(args []string) error {
	return g.fs.Parse(args)
}

func (g *cmdEncrypt) Validate() error {
	if len(g.fileIn) == 0 {
		g.fs.PrintDefaults()
		return errors.New("you must specify at least one input file")
	}
	if g.fileOut == "" {
		g.fs.PrintDefaults()
		return errors.New("you must specify the output ciphered file destination")
	}
	return nil
}

func (g *cmdEncrypt) Run() error {
	var dkps []covert.DataKeyPair
	// ask for the keys here
	for _, f := range g.fileIn {
		var err error
		if g.passphrase == "" {
			g.passphrase, err = readPassword(f)
			if err != nil {
				return err
			}
		}

		cleartext, err := ioutil.ReadFile(f)
		if err != nil {
			panic(err.Error())
		}

		dkp := covert.DataKeyPair{
			Message:    cleartext,
			Passphrase: g.passphrase,
		}

		dkps = append(dkps, dkp)
	}

	f, err := os.Create(g.fileOut)
	if err != nil {
		panic(err.Error())
	}
	defer f.Close()

	d := covert.New(3)
	ciphertext, err := d.Encrypt(dkps)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("writing to %s\n", g.fileOut)

	_, err = f.Write(ciphertext)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("success.")

	return nil
}

type fileInputArrayFlag []string

func (fii *fileInputArrayFlag) String() string {
	return strings.Join(*fii, ", ")
}

func (fii *fileInputArrayFlag) Set(value string) error {
	*fii = append(*fii, value)
	return nil
}
