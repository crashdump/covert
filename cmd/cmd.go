package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

var usage = `usage: covert [--version] [--help]

encrypt - encrypt the given file(s) into a series volume, you can specifie as many -in/-key pair as you need.
    
    -in 	name of the file to be encrypted
    -key	secret key to use to encrypt the data

	example: encrypt -in example.txt -key my-secret-key

decrypt - search for a volume matching the given key and output the data to a file if found.

	example: decrypt -out example.txt -key my-secret-key
`

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Println("\nError:", err)
		os.Exit(1)
	}

	flag.Bool("help", false, "display the usage")
	flag.Bool("version", false, "display the version")
	flag.Parse()
}

type Runner interface {
	Init([]string) error
	Name() string
	Validate() error
	Run() error
}

func root(args []string) error {
	if len(args) < 1 {
		return errors.New(usage)
	}

	fmt.Println(args)

	subcommand := args[0]

	cmds := []Runner{
		NewEncryptCmd(),
		NewDecryptCmd(),
	}

	for _, cmd := range cmds {
		if cmd.Name() == subcommand {
			var err error
			err = cmd.Init(args[1:])
			if err != nil {
				return err
			}

			err = cmd.Validate()
			if err != nil {
				return err
			}

			return cmd.Run()
		}
	}

	return fmt.Errorf("unknown subcommand: %s", subcommand)
}
