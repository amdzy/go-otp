package gotp

import (
	"crypto/rand"
	"math"
)

const maxBufLen = 2048

const minBufLen = 16

func estimatedBufLen(need, maxByte int) int {
	return int(math.Ceil(float64(need) * (255 / float64(maxByte))))
}

func pickRandomChars(length int, chars []byte) []byte {
	if length == 0 {
		return nil
	}

	cLen := len(chars)
	maxRB := 255 - (256 % cLen)
	bufLen := estimatedBufLen(length, maxRB)
	if bufLen < length {
		bufLen = length
	}

	if bufLen > maxBufLen {
		bufLen = maxBufLen
	}

	buf := make([]byte, bufLen)
	out := make([]byte, length)
	i := 0
	for {
		if _, err := rand.Read(buf[:bufLen]); err != nil {
			panic("error reading random bytes: " + err.Error())
		}
		for _, rb := range buf[:bufLen] {
			c := int(rb)
			if c > maxRB {
				continue
			}
			out[i] = chars[c%cLen]
			i++
			if i == length {
				return out
			}
		}
		bufLen = estimatedBufLen(length-i, maxRB)
		if bufLen < minBufLen && minBufLen < cap(buf) {
			bufLen = minBufLen
		}
		if bufLen > maxBufLen {
			bufLen = maxBufLen
		}
	}
}

func RandomSecretBase32() string {
	chars := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	secret := pickRandomChars(32, chars)
	return string(secret)
}

func RandomSecretHex() string {
	chars := []byte("ABCDEF0123456789")
	secret := pickRandomChars(40, chars)
	return string(secret)
}
