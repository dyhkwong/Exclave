package libcore

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// Do not return ([]byte, error) until Go 1.26
func PemToDer(input string) []byte {
	var der []byte
	data := []byte(input)
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil
		}
		der = append(der, block.Bytes...)
		data = rest
	}
	return der
}

// Do not return (string, error) until Go 1.26
func DerToPem(input []byte) string {
	certs, err := x509.ParseCertificates(input)
	if err != nil {
		return ""
	}
	var builder strings.Builder
	for _, cert := range certs {
		if err := pem.Encode(&builder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return ""
		}
	}
	return builder.String()
}
