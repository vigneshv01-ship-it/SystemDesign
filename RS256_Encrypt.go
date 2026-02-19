package main

import (
	"fmt"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func generateKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Generate a new RSA private key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	//Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

func sender(message []byte, publicKey *rsa.PublicKey) []byte {
	
	// Encrypting a secret so only the Private Key owner can read it
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)

	fmt.Println("Ciphertext:", ciphertext)
	
	return ciphertext
}	

func receiver(ciphertext []byte, privateKey *rsa.PrivateKey) []byte {
	// Decrypting that secret
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return nil
	}
	fmt.Println("Decrypted message:", string(plaintext))
	return plaintext
}

func main() {
	privateKey, publicKey, err := generateKeys()
	if err != nil {
		fmt.Println("Key generation failed:", err)
		return
	}
	message := []byte("Hello, World!")

	
	// Encrypting a secret so only the Private Key owner can read it
	ciphertext := sender(message, publicKey)

	// Decrypting that secret
	receiver(ciphertext, privateKey)


}