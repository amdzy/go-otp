package gotp

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net/url"
	"slices"
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
