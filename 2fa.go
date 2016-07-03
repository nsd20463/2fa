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
	"time"
)

// TOTP is the heart of the bit twiddling. It
// computes the current one-time-password given
// the shared secret with the other side.
// The shared secret is base-32-encoded.
func TOTP(shared_secret string) string {
	// compute seconds since the 1st day of our lord of unix
	seconds := time.Now().Unix()

	// GoogleAuthenticator uses 30-second windows, implemented by
	// expressing time as the number of 30-second intervals since
	// the unix zero-time
	counter := uint64(seconds) / 30

	return TOPT_counter(shared_secret, counter)
}

// inner part of TOPT() broken out so it can be unit tested
func TOPT_counter(shared_secret string, counter uint64) string {
	// convert shared_secret to binary
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

	fmt.Printf("secret = % x (%q)\n", secret, secret)
	fmt.Printf("counter = %v\n", counter)
	fmt.Printf("data = % x\n", data)
	fmt.Printf("bytes = % x\n", bytes)
	fmt.Printf("offset = %v\n", offset)
	fmt.Printf("otp = %v\n", otp)

	// the OTP is expressed as a 6 digit decimal number (think of a PIN)
	// the upper digits are discarded
	return fmt.Sprintf("%06d", otp%10000)
}

func main() {

	str := "Hello world....\x00"
	fmt.Println(str, "=", base32.StdEncoding.EncodeToString([]byte(str)))

	if len(os.Args) < 2 {
		os.Stderr.WriteString("2fa <base32 shared secret>\n")
		os.Exit(1)
	}

	fmt.Println(TOTP(os.Args[1]))
}
