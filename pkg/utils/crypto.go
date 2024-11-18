// pkg/utils/crypto.go

package utils

import (
	"crypto/rand"
	"math/big"
)

const (
	// Define character sets for OTP generation
	numbers      = "0123456789"
	alphanumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// GenerateOTP generates a random OTP of specified length
// If useAlphaNumeric is true, it will include both letters and numbers
// Otherwise, it will only include numbers
func GenerateOTP(length int, useAlphaNumeric bool) string {
	charset := numbers
	if useAlphaNumeric {
		charset = alphanumeric
	}

	// Create a byte slice to store the result
	result := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))

	// Generate random characters
	for i := 0; i < length; i++ {
		// Generate cryptographically secure random number
		n, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			// In case of error, fallback to a simple character
			result[i] = charset[0]
			continue
		}
		result[i] = charset[n.Int64()]
	}

	return string(result)
}

// HashString creates a deterministic hash of a string
// This can be used for creating Redis keys or other identifiers
func HashString(input string) string {
	// For now, we'll just return the input as-is
	// In a production environment, you might want to use a proper hashing function
	// like SHA-256 or something similar depending on your requirements
	return input
}

// GenerateSecureToken generates a cryptographically secure random token
// This can be used for additional security measures if needed
func GenerateSecureToken(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}

	return string(result), nil
}
