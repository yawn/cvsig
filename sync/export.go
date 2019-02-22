package sync

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/yawn/cvsig/certificate"
	"github.com/pkg/errors"
)

const (
	errFailedToAddTagsToCertificate = "failed to add tags to ACM server certificate"
	errFailedToEncryptCAPrivateKey  = "failed to KMS encrypt CA private key"
	errFailedToImportCertificate    = "failed to import server certificate to ACM"
)

type Export struct {
	EncryptionContext map[string]*string
	KeyID             string
	Region            string
	Tags              map[string]*string
}

// ExportServer exports the CA signed server certificate to ACM. It returns
// the ID of the ACM certificate if successful.
func (e *Export) ExportServer(ca, server *certificate.Certificate) (*string, error) {

	var (
		chain  = ca.EncodeCertificate()
		cert   = server.EncodeCertificate()
		secret = server.EncodePrivateKey()
	)

	client := acm.New(session.New(&aws.Config{
		Region: &e.Region,
	}))

	req := &acm.ImportCertificateInput{
		Certificate:      []byte(cert),
		CertificateChain: []byte(chain),
		PrivateKey:       []byte(secret),
	}

	res, err := client.ImportCertificate(req)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToImportCertificate)
	}

	if e.Tags != nil {

		var tags []*acm.Tag

		for k, v := range e.Tags {

			tags = append(tags, &acm.Tag{
				Key:   &k,
				Value: v,
			})

		}

		req := &acm.AddTagsToCertificateInput{
			CertificateArn: res.CertificateArn,
			Tags:           tags,
		}

		_, err = client.AddTagsToCertificate(req)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToAddTagsToCertificate)
		}

	}

	return res.CertificateArn, nil

}

// ExportCA exports the CA configuration artifacts (the certificate and the
// KMS encrypted private key.
func (e *Export) ExportCA(ca *certificate.Certificate) (*string, *string, error) {

	chain := ca.EncodeCertificate()

	client := kms.New(session.New(&aws.Config{
		Region: &e.Region,
	}))

	req := &kms.EncryptInput{
		EncryptionContext: e.EncryptionContext,
		KeyId:             &e.KeyID,
		Plaintext:         x509.MarshalPKCS1PrivateKey(ca.Secret),
	}

	res, err := client.Encrypt(req)

	if err != nil {
		return nil, nil, errors.Wrapf(err, errFailedToEncryptCAPrivateKey)
	}

	secret := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: res.CiphertextBlob,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AWS-KMS",
		},
	}))

	return &chain, &secret, nil

}
