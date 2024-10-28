Gotp
============================================

Gotp is a Python library for generating and verifying one-time passwords. It can be used to implement two-factor (2FA)
or multi-factor (MFA) authentication methods in web applications and in other systems that require users to log in.

Open MFA standards are defined in `RFC 4226 <https://tools.ietf.org/html/rfc4226>`_ (HOTP: An HMAC-Based One-Time
Password Algorithm) and in `RFC 6238 <https://tools.ietf.org/html/rfc6238>`_ (TOTP: Time-Based One-Time Password
Algorithm). Gotp implements server-side support for both of these standards. Client-side support can be enabled by
sending authentication codes to users over SMS or email (HOTP) or, for TOTP, by instructing users to use `Google
Authenticator <https://en.wikipedia.org/wiki/Google_Authenticator>`_, `Authy <https://www.authy.com/>`_, or another
compatible app. Users can set up auth tokens in their apps easily by using their phone camera to scan `otpauth://
<https://github.com/google/google-authenticator/wiki/Key-Uri-Format>`_ QR codes provided by Gotp.

Implementers should read and follow the `HOTP security requirements <https://tools.ietf.org/html/rfc4226#section-7>`_
and `TOTP security considerations <https://tools.ietf.org/html/rfc6238#section-5>`_ sections of the relevant RFCs. At
minimum, application implementers should follow this checklist:

- Ensure transport confidentiality by using HTTPS
- Ensure HOTP/TOTP secret confidentiality by storing secrets in a controlled access database
- Deny replay attacks by rejecting one-time passwords that have been used by the client (this requires storing the most
  recently authenticated timestamp, OTP, or hash of the OTP in your database, and rejecting the OTP when a match is
  seen)
- Throttle (rate limit) brute-force attacks against your application's login functionality (see RFC 4226, section 7.3)

We also recommend that implementers read the
`OWASP Authentication Cheat Sheet
<https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md>`_ and
`NIST SP 800-63-3: Digital Authentication Guideline <https://pages.nist.gov/800-63-3/>`_ for a high level overview of
authentication best practices.

[GOTP](https://github.com/amdzy/go-otp)  was inspired by PyOTP.

Quick overview of using One Time Passwords on your phone
--------------------------------------------------------

* OTPs involve a shared secret, stored both on the phone and the server
* OTPs can be generated on a phone without internet connectivity
* OTPs should always be used as a second factor of authentication (if your phone is lost, you account is still secured
  with a password)
* Google Authenticator and other OTP client apps allow you to store multiple OTP secrets and provision those using a QR
  Code
