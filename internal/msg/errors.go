package msg

import "errors"

// Errors messages
var (
	// ErrPkcs7InvalidBlockSize indicates hash blocksize <= 0.
	ErrPkcs7InvalidBlockSize = errors.New("invalid blocksize")
	// ErrPkcs7InvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrPkcs7InvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")
	// ErrPkcs7InvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrPkcs7InvalidPKCS7Padding = errors.New("invalid padding on input")
)