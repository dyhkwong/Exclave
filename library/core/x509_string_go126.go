//go:build go1.26

package libcore

import (
	"crypto/x509"
)

func keyUsageToString(i x509.KeyUsage) string {
	return i.String()
}

func extKeyUsageToString(i x509.ExtKeyUsage) string {
	return i.String()
}
