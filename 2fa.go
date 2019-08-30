/*
  google authenticator commandline client
  2FA (two factor authentication)

  There are lots of open source implementations.
  This is mine so that
    1) I learn how it all works, and
	2) I can tweak it to be just what I want
	3) (maybe it should be a part of my pwsafe)

  Copyright 2016 Nicolas S. Dade
*/

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// TOTP is the heart of the bit twiddling. It
// computes the current one-time-password given
// the shared secret with the other side.
// The shared secret is base-32-encoded.
func TOTP(shared_secret string, digits int) string {
	// compute seconds since the 1st day of our lord of unix
	seconds := time.Now().Unix()

	// GoogleAuthenticator uses 30-second windows, implemented by
	// expressing time as the number of 30-second intervals since
	// the unix zero-time
	counter := uint64(seconds) / 30

	return TOPT_inner(shared_secret, counter, digits)
}

// inner part of TOPT() broken out so it can be unit tested
func TOPT_inner(shared_secret string, counter uint64, digits int) string {
	// convert shared_secret to binary
	// some websites present the secret broken into blocks with spaces
	// and some print in lowercase when base-32 only uses uppercase letters
	// so fix both of those details so it is clean base-32
	shared_secret = strings.ToUpper(shared_secret)
	shared_secret = strings.Map(func(r rune) rune {
		switch {
		case r == ' ':
			return -1
		default:
			return r
		}
	}, shared_secret)

	secret, err := base32.StdEncoding.DecodeString(shared_secret)
	if err != nil {
		log.Fatalln("Couldn't parse the secret as base32:", err)
	}

	// the OTP is constructed from HMAC(SHA1, key=<given secret>, data=<counter as 64-bit big-endian value>)
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, counter)

	hasher := hmac.New(sha1.New, secret)
	hasher.Write(data)
	bytes := hasher.Sum(nil)

	// OTP is a uint32 extracted starting at the byte indicated by the lower 4 bits, with the top bit zeroed
	offset := bytes[sha1.Size-1] & 15 // since SHA1 returns 20 bytes this works without overflowing
	otp := binary.BigEndian.Uint32(bytes[offset : offset+4])
	otp &^= 1 << 31

	// the OTP is expressed as an N digit decimal number (think of a PIN), which means
	// only 10 digits are possible, and 10 isn't good since the first digit can only be 0, 1 or 2.
	// So only allow 1 through 9.
	if digits < 1 || digits >= 10 {
		log.Fatalf("Too many digits (%d) requested. The TOPT algorithm only generates PINs up to 9 digits long.", digits)
	}
	modulo := uint32(1)
	for i := 0; i < digits; i++ {
		modulo *= 10
	}
	format := fmt.Sprintf("%%0%dd", digits)
	pin := fmt.Sprintf(format, otp%modulo)

	if false { // debug code
		fmt.Printf("shared_secret = %q\n", shared_secret)
		fmt.Printf("counter = %v\n", counter)
		fmt.Printf("digits = %v\n", digits)
		fmt.Printf("secret = % x (%q)\n", secret, secret)
		fmt.Printf("data = % x\n", data)
		fmt.Printf("bytes = % x\n", bytes)
		fmt.Printf("offset = %v\n", offset)
		fmt.Printf("otp = %v\n", otp)
		fmt.Printf("modulo = %v\n", modulo)
		fmt.Printf("format = %q\n", format)
		fmt.Printf("pin = %q\n", pin)
	}

	return pin
}

func help(return_code int) {
	os.Stderr.WriteString("2fa <base32 shared secret> [# of digits in PIN] [verify]\n")
	os.Exit(return_code)
}

func main() {
	if len(os.Args) < 2 {
		help(1)
	}
	switch os.Args[1] {
	case "-h", "--help", "-help":
		help(0)
	}

	verify := false
	if len(os.Args) >= 3 && os.Args[len(os.Args)-1] == "verify" {
		verify = true
		os.Args = os.Args[:len(os.Args)-1]
	}

	digits := 6
	if len(os.Args) >= 3 {
		arg := os.Args[len(os.Args)-1]
		tentative_digits, err := strconv.Atoi(arg)
		if err == nil {
			digits = tentative_digits
			os.Args = os.Args[:len(os.Args)-1]
		}
	}

	// the remain arg(s) are the shared secret. It's usually just one long word,
	// but some websites present it as a series of 4-character words which need to be concatenated together.
	shared_secret := strings.Join(os.Args[1:], "")

	if verify {
		fmt.Println("verification code: ", TOPT_inner(shared_secret, 0, digits))
	} else {
		fmt.Println(TOTP(shared_secret, digits))
	}
}
