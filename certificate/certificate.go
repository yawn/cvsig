package certificate

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type Certificate struct {
	Cert   []byte
	Config *x509.Certificate
	Public *rsa.PublicKey
	Secret *rsa.PrivateKey
}

func (c *Certificate) EncodeCertificate() string {

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Cert,
	}))

}

func (c *Certificate) EncodePrivateKey() string {

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.Secret),
	}))

}
