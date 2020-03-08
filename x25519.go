// A small helper library to make X25519 key agreement algorithm easier
package x25519

import (
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
)

// The structure that holds public key and secret key. Share public key to perform key agreement. Do not share the secret key
type KeyPair struct {
	PublicKey []byte // share this value with anyone you like!
	SecretKey []byte // keep this one secret
}

// Generates a public key and a secret for key agreement
func NewX25519() (*KeyPair, error) {
	// read more: https://cr.yp.to/ecdh.html
	// create a new key structure
	key := &KeyPair{
		PublicKey: make([]byte, 32), // both public and private keys are 32 bytes
		SecretKey: make([]byte, 32), // both public and private keys are 32 bytes
	}
	// randomly fill secret key with crypto/rand
	_, err := rand.Read(key.SecretKey)
	if err != nil {
		return nil, err
	}
	// as defined in https://cr.yp.to/ecdh.html do these operation to finalize the private key
	key.SecretKey[0] &= 248
	key.SecretKey[31] &= 127
	key.SecretKey[31] |= 64
	// compute the public key
	key.PublicKey, err = curve25519.X25519(key.SecretKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	// return the key
	return key, nil
}

// Generate a key pair (public key) from private key
func NewX25519FromPrivateKey(privateKey []byte) (*KeyPair, error) {
	key := &KeyPair{
		PublicKey: nil,
		SecretKey: privateKey,
	}
	// compute the public key
	var err error
	key.PublicKey, err = curve25519.X25519(key.SecretKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	// return the key
	return key, nil
}

// Calculates a shared secret given with the other user's public key
func (key *KeyPair) GenerateSharedSecret(otherPublicKey []byte) ([]byte, error) {
	return curve25519.X25519(key.SecretKey, otherPublicKey)
}
