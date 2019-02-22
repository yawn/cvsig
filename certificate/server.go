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

const errFailedToGenerateServerKey = "failed to generate server private key"

// NewServer generates a new certificate authority
func NewServer(ca *Certificate, name string) (*Certificate, error) {

	config := &x509.Certificate{
		DNSNames:     []string{name},
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             now,
		NotAfter:              now.Add(100 * 365 * 24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	secret, err := rsa.GenerateKey(rand.Reader, keysize)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToGenerateServerKey)
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
