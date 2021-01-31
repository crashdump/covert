package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

var usage = `usage: covert [--version] [--help]

encrypt - encrypt the given file(s) into a series volume, you can specify as many input file(s) as
you need. Covert recommend at least one decoy, but it's not mandatory.

    -input 	              name of the file(s) to be encrypted
    -garbage-partitions   number of garbage partitions you would like (defaults to 1)

	example: encrypt -input secret.txt -input decoy.txt

decrypt - search for a volume matching the given key and output the data to a file if found.

	example: decrypt -out example.txt
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
