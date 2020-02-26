package x25519

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestNormal(t *testing.T) {
	// generate keys
	alice, err := NewX25519()
	if err != nil{
		t.Fatalf("could not genearte key for alice: %s",err.Error())
	}
	bob, err := NewX25519()
	if err != nil{
		t.Fatalf("could not genearte key for bob: %s",err.Error())
	}
	// calculate secret
	s1, err := alice.GenerateSharedSecret(bob.PublicKey)
	if err != nil{
		t.Fatalf("could not get secret for alice: %s",err.Error())
	}
	s2, err := bob.GenerateSharedSecret(alice.PublicKey)
	if err != nil{
		t.Fatalf("could not get secret for bob: %s",err.Error())
	}
	// check if they match
	if ! bytes.Equal(s1,s2){
		t.Errorf("secrets do not match")
	}
}

func TestNewX25519FromPrivateKey(t *testing.T) {
	key1, _ := base64.StdEncoding.DecodeString("sECe8YYQT/bODurKruM8QpGFBTahurW8GqxFL+AYiW8=")
	key2, _ := base64.StdEncoding.DecodeString("wAidyKs9iF+KA1cgBxa1rMtPwemOLFHqSIe5nkVRN2o=")
	secret, _ := base64.StdEncoding.DecodeString("dbfEcOMjYactMkh33DRhg0h1VCbmhxoWt6AR3rp6000=")
	// generate keys
	alice,err := NewX25519FromPrivateKey(key1)
	if err != nil{
		t.Fatalf("could not get public key for alice: %s",err.Error())
	}
	bob,err := NewX25519FromPrivateKey(key2)
	if err != nil{
		t.Fatalf("could not get public key for bob: %s",err.Error())
	}
	// calculate secret
	s1, err := alice.GenerateSharedSecret(bob.PublicKey)
	if err != nil{
		t.Fatalf("could not get secret for alice: %s",err.Error())
	}
	s2, err := bob.GenerateSharedSecret(alice.PublicKey)
	if err != nil{
		t.Fatalf("could not get secret for bob: %s",err.Error())
	}
	// check if they match
	if ! bytes.Equal(s1,s2){
		t.Errorf("secrets do not match")
	}
	if ! bytes.Equal(s1,secret){
		t.Errorf("secret is not the one that should be")
	}
}

func TestNewX25519FromPrivateKey2(t *testing.T) {
	private, _ := base64.StdEncoding.DecodeString("aF9hmPSeJfKvjPam++gl7MRIQydQQu2Jdee8zOTX+lY=")
	public, _ := base64.StdEncoding.DecodeString("FTM52WXsEjj5hBY53RTUFmG2qUwzZxPRJdYs9lu/y3M=")
	// generate keys
	key,err := NewX25519FromPrivateKey(private)
	if err != nil{
		t.Fatalf("could not get public key: %s",err.Error())
	}
	// check if they match
	if ! bytes.Equal(key.PublicKey,public){
		t.Errorf("public keys do not match")
	}
}