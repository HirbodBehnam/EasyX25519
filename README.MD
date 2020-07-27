# Easy X25519
![Go](https://github.com/HirbodBehnam/EasyX25519/workflows/Go/badge.svg)

A simple way to do x25519 key agreements.
## Why this?
* Easy to use
* Use [curve25519.X25519](https://godoc.org/golang.org/x/crypto/curve25519#X25519) for multiplication and not other deprecated methods.
* Small code base
* Use slices of byte instead of [32]byte
## Installing
```
go get github.com/HirbodBehnam/EasyX25519
```
## Usage
This library has three functions.
1. `NewX25519`: Creates a fresh key pair for x25519 key exchange algorithm.
2. `NewX25519FromPrivateKey`: Creates a key pair from private key
3. `(*KeyPair) GenerateSharedSecret`: Pass the other recipient's public key to this command to generate a shared secret
### Documentation
https://pkg.go.dev/github.com/HirbodBehnam/EasyX25519
### Example
Here is a small example from test file:
```go
package main

import (
	"github.com/HirbodBehnam/EasyX25519"
	"log"
)

func main() {
	// generate keys
	alice, err := x25519.NewX25519()
	if err != nil{
		log.Fatalf("could not genearte key for alice: %s",err.Error())
	}
	log.Printf("Alice public key %x",alice.PublicKey)
	bob, err := x25519.NewX25519()
	if err != nil{
		log.Fatalf("could not genearte key for bob: %s",err.Error())
	}
	log.Printf("Bob public key %x",bob.PublicKey)
	// calculate secret
	s1, err := alice.GenerateSharedSecret(bob.PublicKey)
	if err != nil{
		log.Fatalf("could not get secret for alice: %s",err.Error())
	}
	s2, err := bob.GenerateSharedSecret(alice.PublicKey)
	if err != nil{
		log.Fatalf("could not get secret for bob: %s",err.Error())
	}
	// check if they match
	log.Printf("Alice secret %x",s1)
	log.Printf("Bob secret %x",s2)
}
```
