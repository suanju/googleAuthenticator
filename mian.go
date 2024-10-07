package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

type GoogleAuthenticator struct {
	codeLength int
}

func NewGoogleAuthenticator() *GoogleAuthenticator {
	return &GoogleAuthenticator{
		codeLength: 6,
	}
}

// CreateSecret generates a new secret with the specified length.
func (ga *GoogleAuthenticator) CreateSecret(secretLength int) (string, error) {
	if secretLength < 16 || secretLength > 128 {
		return "", errors.New("bad secret length")
	}

	validChars := ga.getBase32LookupTable()
	secret := make([]byte, secretLength)

	_, err := rand.Read(secret)
	if err != nil {
		return "", errors.New("no source of secure random")
	}

	var result strings.Builder
	for _, b := range secret {
		result.WriteByte(validChars[int(b)&31])
	}

	return result.String(), nil
}

// GetCode calculates the TOTP code using the given secret and time slice.
func (ga *GoogleAuthenticator) GetCode(secret string, timeSlice int64) (string, error) {
	if timeSlice == 0 {
		timeSlice = time.Now().Unix() / 30
	}

	secretKey, err := ga.base32Decode(secret)
	if err != nil {
		return "", err
	}

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeSlice))

	hash := hmac.New(sha1.New, secretKey)
	hash.Write(timeBytes)
	hmacHash := hash.Sum(nil)

	offset := hmacHash[len(hmacHash)-1] & 0x0F
	value := int32(binary.BigEndian.Uint32(hmacHash[offset:offset+4]) & 0x7FFFFFFF)

	modulo := int32(math.Pow10(ga.codeLength))
	return fmt.Sprintf("%06d", value%modulo), nil
}

// VerifyCode checks if the given code is valid for the provided secret and discrepancy.
func (ga *GoogleAuthenticator) VerifyCode(secret string, code string, discrepancy int, currentTimeSlice int64) bool {
	if len(code) != 6 {
		return false
	}

	if currentTimeSlice == 0 {
		currentTimeSlice = time.Now().Unix() / 30
	}

	for i := -discrepancy; i <= discrepancy; i++ {
		calculatedCode, _ := ga.GetCode(secret, currentTimeSlice+int64(i))
		if ga.timingSafeEquals(calculatedCode, code) {
			return true
		}
	}

	return false
}

// Helper function to decode a base32 encoded string.
func (ga *GoogleAuthenticator) base32Decode(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.TrimRight(secret, "="))
	decoded, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// TimingSafeEquals performs a timing-safe string comparison.
func (ga *GoogleAuthenticator) timingSafeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i] ^ b[i])
	}
	return result == 0
}

// GetBase32LookupTable returns the base32 lookup table used for encoding.
func (ga *GoogleAuthenticator) getBase32LookupTable() []byte {
	return []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
}

func main() {
	authenticator := NewGoogleAuthenticator()
	secret, err := authenticator.CreateSecret(16)
	if err != nil {
		fmt.Println("Error creating secret:", err)
		return
	}

	fmt.Println("Generated Secret:", secret)

	code, err := authenticator.GetCode(secret, 0)
	if err != nil {
		fmt.Println("Error generating code:", err)
		return
	}

	fmt.Println("Generated Code:", code)

	isValid := authenticator.VerifyCode(secret, code, 1, 0)
	fmt.Println("Is the code valid?", isValid)
}
