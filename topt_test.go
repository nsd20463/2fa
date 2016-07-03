package main

import (
	"encoding/base32"
	"testing"
)

func TestTOPT_google_authenticator(t *testing.T) {
	// use the test vector given in the google authenticator PAM library source code in:
	//  https://github.com/google/google-authenticator/blob/master/libpam/tests/pam_google_authenticator_unittest.c

	secret := "JBSWY3DPEB3W64TMMQXC4LQA" // the base-32-encoded shared secret
	counter := uint64(10000)             // counter value in uint tests
	correct := "050548"                  // correct OTP

	otp := TOPT_inner(secret, counter, 6)

	if otp != correct {
		t.Errorf("TOPT test vector failed. expected TOPT_counter(%v,%v) = %v; got %v", secret, counter, correct, otp)
	}
}

func TestTOPT_RFC6238(t *testing.T) {
	// use test vectors given in RFC 6238

	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	good := []struct {
		secs uint64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, v := range good {
		otp := TOPT_inner(secret, v.secs/30, len(v.code))
		if otp != v.code {
			t.Errorf("test at secs = %d failed. expected %v; got %v", v.secs, v.code, otp)
		}
	}

}
