package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"time"

	"github.com/pkg/errors"
)

const errFailedToGenerateCAKey = "failed to generate CA private key"

// NewCA generates a new certificate authority
func NewCA(name string) (*Certificate, error) {

	config := &x509.Certificate{
		DNSNames:     []string{name},
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             now,
		NotAfter:              now.Add(100 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	secret, err := rsa.GenerateKey(rand.Reader, keysize)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToGenerateCAKey)
	}

	public := &secret.PublicKey

	config.SubjectKeyId = subjectKeyId(secret)

	certificate, err := x509.CreateCertificate(rand.Reader, config, config, public, secret)

	if err != nil {
		log.Fatal(err)
	}

	return &Certificate{
		Cert:   certificate,
		Config: config,
		Public: public,
		Secret: secret,
	}, nil

}
