package main

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"syscall"
)

func readPassword(filename string) (string, error) {
	var passphrase string
	fmt.Printf("passphrase for %s: ", filename)

	bpassphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	passphrase = string(bpassphrase)
	if len(passphrase) <= 10 {
		return "", errors.New("the secret passphrase must be at least 10 characters")
	}
	return passphrase, err
}
