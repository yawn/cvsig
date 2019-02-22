package sync

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/yawn/cvsig/certificate"
	"github.com/pkg/errors"
)

const (
	errFailedToDecryptCAPrivateKey = "failed to KMS decrypt CA private key"
	errFailedToParseCACertificate  = "failed to parse X509 CA certificate"
	errFailedToParseCAPrivateKey   = "failed to parse X509 CA private key"
)

type Import struct {
	Region            string
	EncryptionContext map[string]*string
}

// ImportCA imports the chain and secret CA into a Certificate struct
func (i *Import) ImportCA(chain, secret string) (*certificate.Certificate, error) {

	c := new(certificate.Certificate)

	{

		block, _ := pem.Decode([]byte(chain))

		cert, err := x509.ParseCertificate(block.Bytes)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToParseCACertificate)
		}

		c.Cert = block.Bytes
		c.Config = cert

	}

	{

		block, _ := pem.Decode([]byte(secret))

		client := kms.New(session.New(&aws.Config{
			Region: &i.Region,
		}))

		req := &kms.DecryptInput{
			CiphertextBlob:    []byte(block.Bytes),
			EncryptionContext: i.EncryptionContext,
		}

		res, err := client.Decrypt(req)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToDecryptCAPrivateKey)
		}

		secret, err := x509.ParsePKCS1PrivateKey(res.Plaintext)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToParseCAPrivateKey)
		}

		c.Secret = secret

	}

	return c, nil

}
