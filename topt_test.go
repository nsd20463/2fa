package main

import (
	"testing"
)

func TestTOPT(t *testing.T) {
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
