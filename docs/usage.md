# Command line usage

```
usage: covert [--version] [--help]

encrypt - encrypt the given file(s) into a series volume, you can specify as many input file(s) as
you need. Covert recommend at least one decoy, but it's not mandatory.

    -input 	          name of the file(s) to be encrypted
    -garbage-partitions   number of garbage partitions you would like (defaults to 1)

	example: encrypt -input secret.txt -input decoy.txt

decrypt - search for a volume matching the given key and output the data to a file if found.

	example: decrypt -out example.txt
```