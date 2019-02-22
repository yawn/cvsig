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

const errFailedToGenerateClientKey = "failed to generate client private key"

// NewClient generates a new client certificate
func NewClient(ca *Certificate, name string) (*Certificate, error) {

	config := &x509.Certificate{
		DNSNames:     []string{name},
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             now,
		NotAfter:              now.Add(12 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	secret, err := rsa.GenerateKey(rand.Reader, keysize)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToGenerateClientKey)
	}

	public := &secret.PublicKey

	config.SubjectKeyId = subjectKeyId(secret)

	certificate, err := x509.CreateCertificate(rand.Reader, config, ca.Config, public, ca.Secret)

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
