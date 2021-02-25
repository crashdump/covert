package main

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/term"
)

func readPassword(filename string) (string, error) {
	var passphrase string
	fmt.Printf("passphrase for %s: ", filename)

	bpassphrase, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	passphrase = string(bpassphrase)
	if len(passphrase) <= 10 {
		return "", errors.New("the secret passphrase must be at least 10 characters")
	}
	return passphrase, err
}
