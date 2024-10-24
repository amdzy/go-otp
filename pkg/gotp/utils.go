package gotp

import (
	"crypto/subtle"
	"encoding/binary"
	"slices"

	"golang.org/x/text/unicode/norm"
)

func intToByte(input uint64) []byte {
	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, input)
	slices.Reverse(bs)
	return bs
}

// Timing-attack resistant string comparison.
func stringsEqual(s1, s2 string) bool {
	s1 = norm.NFKC.String(s1)
	s2 = norm.NFKC.String(s2)

	return subtle.ConstantTimeCompare([]byte(s1), []byte(s2)) == 1
}
