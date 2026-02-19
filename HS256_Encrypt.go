package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// In your app, this comes from an environment variable
var sharedSecret = []byte("your-256-bit-secret-key-here")

func main() {
	message := "user_id=123&role=admin"

	// --- STEP 1: Generate the Signature ---
	signature := generateHS256(message, sharedSecret)
	fmt.Println("Message:", message)
	fmt.Println("HS256 Signature:", signature)

	// --- STEP 2: Verify the Signature ---
	// Imagine this message and signature were sent over the network
	isValid := verifyHS256(message, signature, sharedSecret)
	
	if isValid {
		fmt.Println("Verification Successful: Message is authentic!")
	} else {
		fmt.Println("Verification Failed: Data tampered or wrong key.")
	}
}

func generateHS256(message string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	
	// Returns the raw bytes of the signature
	sha := h.Sum(nil)
	
	// Encode to hex string for easy transport (like in a URL or Header)
	return hex.EncodeToString(sha)
}

func verifyHS256(message string, messageSignature string, secret []byte) bool {
	// 1. Re-generate the signature from the message
	expectedSignature := generateHS256(message, secret)

	// 2. Compare the two signatures
	// NOTE: Use hmac.Equal to prevent "Timing Attacks"
	return hmac.Equal([]byte(expectedSignature), []byte(messageSignature))
}