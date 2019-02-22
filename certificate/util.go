package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"math/big"
	"time"
)

const keysize = 2048

var now = time.Now()

// serial generates a random serial
func serial() *big.Int {

	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

	n, err := rand.Int(rand.Reader, max)

	if err != nil {
		panic(err)
	}

	return n

}

// subjectKeyId generates a hash over the private key suitable for a x509v3 subject key id
func subjectKeyId(pk *rsa.PrivateKey) []byte {

	hash := sha1.New()
	hash.Write(pk.N.Bytes())

	return hash.Sum(nil)

}
