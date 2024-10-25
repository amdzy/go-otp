package gotp

type HOTP struct {
	OTP
	InitialCount int
}

func NewHOTP(secret string, digits int, hasher *Hasher, name, issuer string, initialCount int) (*HOTP, error) {
	otp, err := NewOtp(secret, digits, name, issuer, hasher)
	if err != nil {
		return nil, err
	}

	return &HOTP{OTP: *otp, InitialCount: initialCount}, nil
}

func NewDefaultHOTP(secret string) (*HOTP, error) {
	return NewHOTP(secret, 6, nil, "", "", 0)
}

func (hotp *HOTP) At(count int64) (string, error) {
	return hotp.generateOTP(int64(hotp.InitialCount) + count)
}

func (hotp *HOTP) Verify(otp string, count int64) (bool, error) {
	generatedOtp, err := hotp.At(count)
	if err != nil {
		return false, err
	}

	return stringsEqual(generatedOtp, otp), nil
}

func (hotp *HOTP) ProvisionUri(name, issuer, image string) string {
	return BuildUri(hotp.secret, name, issuer, hotp.hasher.name, image, &hotp.digits, nil, &hotp.InitialCount)
}
