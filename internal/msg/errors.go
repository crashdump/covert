package msg

import "errors"

// Errors messages
var (
	// ErrCovertInvalidAmountPartition indicates number partitions was set too low
	ErrCovertInvalidAmountPartition = errors.New("the minimum amount of partitions is 3")
	// ErrCovertInvalidLengthCleartext indicates cleartext input is 0
	ErrCovertInvalidLengthCleartext = errors.New("cleartext length must be > 0")
	// ErrCovertInvalidLengthPassphrase indicates passphrase input is 0
	ErrCovertInvalidLengthPassphrase = errors.New("passphrase length must be > 0")
	// ErrCovertNoPartitionMacthKey indicates we have not found any data we could decrypt with the key provided
	ErrCovertNoPartitionMacthKey = errors.New("no partitions matching this key were found")

	// ErrPkcs7InvalidBlockSize indicates hash blocksize <= 0.
	ErrPkcs7InvalidBlockSize = errors.New("invalid blocksize")
	// ErrPkcs7InvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrPkcs7InvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")
	// ErrPkcs7InvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrPkcs7InvalidPKCS7Padding = errors.New("invalid padding on input")
)
