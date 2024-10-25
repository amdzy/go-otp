package gotp

import (
	"time"
)

type TOTP struct {
	OTP
	Interval int
}

func NewTOTP(secret string, digits int, hasher *Hasher, name, issuer string, interval int) (*TOTP, error) {
	otp, err := NewOtp(secret, digits, name, issuer, hasher)
	if err != nil {
		return nil, err
	}

	return &TOTP{OTP: *otp, Interval: interval}, nil
}

func NewDefaultTOTP(secret string) (*TOTP, error) {
	return NewTOTP(secret, 6, nil, "", "", 30)
}

func (totp *TOTP) At(timestamp int64) (string, error) {
	return totp.generateOTP(totp.timecode(timestamp))
}

func (totp *TOTP) AtTime(timestamp time.Time) (string, error) {
	return totp.At(timestamp.Unix())
}

func (totp *TOTP) Now() (string, error) {
	return totp.At(time.Now().Unix())
}

func (totp *TOTP) Verify(otp string, timestamp int64) (bool, error) {
	generatedOtp, err := totp.At(timestamp)
	if err != nil {
		return false, err
	}
	return stringsEqual(generatedOtp, otp), nil
}

func (totp *TOTP) VerifyTime(otp string, timestamp time.Time) (bool, error) {
	return totp.Verify(otp, timestamp.Unix())
}

func (totp *TOTP) VerifyNow(otp string) (bool, error) {
	return totp.Verify(otp, time.Now().Unix())
}

func (totp *TOTP) VerifyWithWindow(otp string, timestamp int64, window int) (bool, error) {
	for i := -window; i <= window; i++ {
		isEqual, err := totp.Verify(otp, timestamp+int64(i))
		if err != nil {
			return false, err
		}
		if isEqual {
			return true, nil
		}
	}
	return false, nil
}

func (totp *TOTP) ProvisionUri(name, issuer string) string {
	return BuildUri(totp.secret, name, issuer, totp.hasher.name, &totp.digits, &totp.Interval, nil)
}

func (totp *TOTP) timecode(timestamp int64) int64 {
	return timestamp / int64(totp.Interval)
}
