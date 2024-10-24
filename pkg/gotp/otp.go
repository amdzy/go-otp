package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"hash"
	"math"
	"strconv"
	"strings"
)

type Hasher struct {
	name   string
	digest func() hash.Hash
}

type OTP struct {
	secret string
	digits int
	name   string
	issuer string
	hasher Hasher
}

func NewOtp(secret string, digits int, name, issuer string, hasher *Hasher) (*OTP, error) {
	if digits <= 0 {
		return nil, errors.New("digits must be greater than 0")
	}

	if digits >= 10 {
		return nil, errors.New("digits must be less than 10")
	}

	if name == "" {
		name = "Secret"
	}

	if hasher == nil {
		hasher = &Hasher{
			name:   "sha1",
			digest: sha1.New,
		}
	}

	otp := OTP{
		secret: secret,
		digits: digits,
		name:   name,
		issuer: issuer,
		hasher: *hasher,
	}

	return &otp, nil
}

func (otp *OTP) generateOTP(input int64) (string, error) {
	if input < 0 {
		return "", errors.New("input must be positive integer")
	}

	byteSecret, err := otp.byteSecret()
	if err != nil {
		return "", err
	}

	hasher := hmac.New(otp.hasher.digest, byteSecret)
	hasher.Write(intToByte(uint64(input)))
	hash := hasher.Sum(nil)

	offset := int(hash[len(hash)-1]) & 0xF
	code := (int(hash[offset])&0x7F)<<24 | (int(hash[offset+1])&0xFF)<<16 | (int(hash[offset+2])&0xFF)<<8 | (int(hash[offset+3]) & 0xFF)
	code = code % int(math.Pow10(otp.digits))

	codeStr := strconv.Itoa(code)
	for len(codeStr) < otp.digits {
		codeStr = "0" + codeStr
	}

	return codeStr, nil
}

func (otp *OTP) byteSecret() ([]byte, error) {
	secret := otp.secret
	missingPadding := len(secret) % 8
	if missingPadding != 0 {
		secret += strings.Repeat("=", (8 - missingPadding))
	}

	return base32.StdEncoding.DecodeString(strings.ToUpper(secret))
}
