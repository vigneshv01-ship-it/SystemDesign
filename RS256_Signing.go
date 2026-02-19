package main

import (
	"fmt"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func generateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	// Generate a new RSA private key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	//Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey
}

func sender(hashed [32]byte, privateKey *rsa.PrivateKey) ([]byte, [32]byte) {
		// Sender signs the hashed message using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("Error signing message:", err)
		return nil, hashed
	}
	fmt.Println("Signature:", signature)

	return signature, hashed
}

func receiver(signature []byte, hashed [32]byte, publicKey *rsa.PublicKey) (bool) {
	// Receiver verifies the signature using the public key
	isValid := true
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println("Signature verification failed:", err)
		isValid = false
	} else {
		fmt.Println("Signature verification successful!")
		isValid = true
	}
	return isValid
}


func main() {
	privateKey, publicKey := generateKeys()

	message := []byte("Hello, World!")

	// Hash the message using SHA-256
	hashed := sha256.Sum256(message)

	fmt.Println("Hashed Message:", hashed)

	// Sender signs the hashed message using the private key
	signature, hashed := sender(hashed, privateKey)

	// Receiver verifies the signature using the public key
	if(signature == nil) {
		fmt.Println("Message signing failed. Cannot proceed with verification.")
		return
	}
	isValid := receiver(signature, hashed, publicKey)

	if(isValid) {
		fmt.Println("Message is authentic and has not been tampered with.")
	} else {
		fmt.Println("Message authenticity could not be verified.")
	}
}