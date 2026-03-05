package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate key pair: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PUBLIC_KEY=%s\n", hex.EncodeToString(pub))
	fmt.Printf("PRIVATE_KEY=%s\n", hex.EncodeToString(priv))
}
