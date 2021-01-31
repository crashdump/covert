package pkcs7

import (
	"bytes"
	"github.com/crashdump/covert/internal/msg"
)

// Pad right-pads the given byte slice with 1 to n bytes, where n is the
// block size. The size of the result is x times n, where x is at least 1.
func Pad(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, msg.ErrPkcs7InvalidBlockSize
	}

	if len(b) == 0 {
		return nil, msg.ErrPkcs7InvalidPKCS7Data
	}

	n := blockSize - (len(b) % blockSize)
	pb := make([]byte, len(b)+n)

	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))

	return pb, nil
}

// Unpad validates and unpads data from the given bytes slice. The returned
// value will be 1 to n bytes smaller depending on the amount of padding,
// where n is the block size.
func Unpad(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, msg.ErrPkcs7InvalidBlockSize
	}

	if len(b) == 0 {
		return nil, msg.ErrPkcs7InvalidPKCS7Data
	}

	if len(b)%blockSize != 0 {
		return nil, msg.ErrPkcs7InvalidPKCS7Padding
	}

	c := b[len(b)-1]
	n := int(c)

	if n == 0 || n > len(b) {
		return nil, msg.ErrPkcs7InvalidPKCS7Padding
	}

	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, msg.ErrPkcs7InvalidPKCS7Padding
		}
	}

	return b[:len(b)-n], nil
}
