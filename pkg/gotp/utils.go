package gotp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

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

func BuildUri(secret, name, issuer, algorithm string, digits, period, initialCount *int) string {
	q := url.Values{}

	otpType := "totp"
	if initialCount != nil {
		otpType = "hotp"
	}

	label := url.PathEscape(name)
	if issuer != "" {
		label = issuer + ":" + label
		q.Add("issuer", url.QueryEscape(issuer))
	}

	if initialCount != nil {
		q.Add("counter", fmt.Sprint(*initialCount))
	}

	if algorithm != "" && algorithm != "sha1" {
		q.Add("algorithm", strings.ToUpper(algorithm))
	}

	if digits != nil && *digits != 6 {
		q.Add("digits", fmt.Sprint(*digits))
	}

	if period != nil && *period != 30 {
		q.Add("period", fmt.Sprint(*period))
	}

	q.Add("secret", secret)

	u := url.URL{
		Scheme:   "otpauth",
		Host:     otpType,
		Path:     label,
		RawQuery: q.Encode(),
	}

	return u.String()
}

type generator interface {
	At(int64) (string, error)
	Verify(string, int64) (bool, error)
	ProvisionUri(string, string) string
}

func ParseUri(uri string) (generator, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "otpauth" {
		return nil, errors.New("invalid uri")
	}

	name := ""
	issuer := ""
	digits := 6
	period := 30
	counter := 0
	hasher := Hasher{name: "sha1", digest: sha1.New}

	accountInfo := strings.Split(u.Path, ":")
	if len(accountInfo) == 1 {
		name = accountInfo[0]
	} else {
		name = accountInfo[0]
		issuer = accountInfo[1]
	}

	q := u.Query()

	secret := q.Get("secret")
	if secret == "" {
		return nil, errors.New("no secret found in URI")
	}

	if q.Get("digits") != "" {
		n, err := strconv.Atoi(q.Get("digits"))
		if err != nil {
			return nil, err
		}
		digits = n
	}

	if q.Get("period") != "" {
		n, err := strconv.Atoi(q.Get("period"))
		if err != nil {
			return nil, err
		}
		period = n
	}

	if q.Get("counter") != "" {
		d, err := strconv.Atoi(q.Get("counter"))
		if err != nil {
			return nil, err
		}
		counter = d
	}

	if q.Get("algorithm") != "" {
		value := q.Get("algorithm")
		if value == "SHA1" {
			hasher = Hasher{name: "sha1", digest: sha1.New}
		}
		if value == "SHA256" {
			hasher = Hasher{name: "sha256", digest: sha256.New}
		}
		if value == "SHA512" {
			hasher = Hasher{name: "sha512", digest: sha512.New}
		}
	}

	if u.Host == "totp" {
		return NewTOTP(secret, digits, &hasher, name, issuer, period)
	}
	if u.Host == "hotp" {
		return NewHOTP(secret, digits, &hasher, name, issuer, counter)
	}

	return nil, errors.New("not a supported otp type")
}
