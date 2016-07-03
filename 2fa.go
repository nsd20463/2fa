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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"
)

// TOTP is the heart of the bit twiddling. It
// computes the current one-time-password given
// the shared secret with the other side.
// The shared secret is base-64-encoded.
func TOTP(shared_secret string) string {
	// convert shared_secret to binary
	secret, err := base64.StdEncoding.DecodeString(shared_secret)
	if err != nil {
		log.Fatalln("Couldn't parse the secret as base64:", err)
	}

	// compute seconds since the 1st day of our lord of unix
	seconds := time.Now().Unix()

	// GoogleAuthenticator uses 30-second windows, implemented by
	// expressing time as the number of 30-second intervals since
	// the unix zero-time
	count := uint64(seconds) / 30

	// the OTP is built from SHA1_HMAC(key=<given secret>, data=<count as 64-bit big-endian number>)
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], count)
	bytes := hmac.New(sha1.New, secret).Sum(data[:])
	// OTP is a uint32 extracted starting at the byte indicated by the lower 4 bits, with the top bit zeroed
	offset := bytes[sha1.Size-1] & 15
	otp := uint32(bytes[offset])<<24 + uint32(bytes[offset+1])<<16 + uint32(bytes[offset+2])<<8 + uint32(bytes[offset+3])
	otp &^= 1 << 31

	fmt.Printf("secret = % x\n", secret)
	fmt.Printf("seconds = %v\n", seconds)
	fmt.Printf("count = %v\n", count)
	fmt.Printf("data = % x\n", data)
	fmt.Printf("bytes = % x\n", bytes)
	fmt.Printf("offset = %v\n", offset)
	fmt.Printf("otp = %v\n", otp)

	// the OTP is expressed as a 6 to 8 digit decimal number (think of a PIN)
	// the upper digits are discarded
	return fmt.Sprintf("%08d", otp%1000000)
}

func main() {
	if len(os.Args) < 2 {
		os.Stderr.WriteString("2fa <base64 shared secret>\n")
		os.Exit(1)
	}

	fmt.Println(TOTP(os.Args[1]))
}
