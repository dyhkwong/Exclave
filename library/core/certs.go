/*
Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package libcore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	_ "unsafe"
)

func init() {
	// crypto/x509 once.Do(initSystemRoots)
	x509.SystemCertPool()
}

const (
	caProviderMozilla = iota
	caProviderSystem
	caProviderSystemAndUser // for https://github.com/golang/go/issues/71258
	caProviderCustom
)

//go:linkname systemRoots crypto/x509.systemRoots
var systemRoots *x509.CertPool

func setupMozillaCAProvider() error {
	if err := extractMozillaCAPem(); err != nil {
		return err
	}
	pemFile, err := os.ReadFile(internalAssetsPath + mozillaIncludedPem)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemFile) {
		return newError("failed to append certificates from pem")
	}
	systemRoots = roots
	return nil
}

func setupCustomCAProvider() error {
	pemFile, err := os.ReadFile(externalAssetsPath + customPem)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemFile) {
		return newError("failed to append certificates from pem")
	}
	systemRoots = roots
	return nil
}

func UpdateSystemRoots(caProvider int32) error {
	assetsAccess.Lock()
	defer assetsAccess.Unlock()
	switch caProvider {
	case caProviderSystem:
		var err error
		systemRoots, err = x509.SystemCertPool()
		if err != nil {
			systemRoots = x509.NewCertPool()
			return newError("setup system root store").Base(err)
		}
	case caProviderMozilla:
		if err := setupMozillaCAProvider(); err != nil {
			systemRoots = x509.NewCertPool()
			return newError("setup mozilla root store").Base(err)
		}
	case caProviderCustom:
		if err := setupCustomCAProvider(); err != nil {
			systemRoots = x509.NewCertPool()
			return newError("setup custom root store").Base(err)
		}
	case caProviderSystemAndUser:
		if err := setupSystemAndUserCAProvider(); err != nil {
			systemRoots = x509.NewCertPool()
			return newError("setup system and user store").Base(err)
		}
	default:
		systemRoots = x509.NewCertPool()
		return newError("unknown root store provider")
	}
	return nil
}

func setupSystemAndUserCAProvider() error {
	// inspired by https://github.com/chenxiaolong/RSAF
	paths := make(map[string]string)

	systemDir := "/apex/com.android.conscrypt/cacerts" // Android 14+
	entries, err := os.ReadDir(systemDir)
	if err != nil {
		systemDir = "/system/etc/security/cacerts"
		entries, err = os.ReadDir(systemDir)
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		paths[entry.Name()] = systemDir + "/" + entry.Name()
	}

	userId := os.Getuid() / 100000
	userDir := fmt.Sprintf("/data/misc/user/%d/cacerts-added", userId)
	if entries, err = os.ReadDir(userDir); err == nil {
		for _, entry := range entries {
			paths[entry.Name()] = userDir + "/" + entry.Name()
		}
	}
	if entries, err = os.ReadDir(fmt.Sprintf("/data/misc/user/%d/cacerts-removed", userId)); err == nil {
		for _, entry := range entries {
			delete(paths, entry.Name())
		}
	}

	if err := os.MkdirAll(internalAssetsPath, 0666); err != nil {
		return newError("make dir").Base(err)
	}
	pemFile, err := os.Create(internalAssetsPath + androidIncludedPem) // for plugins
	if err != nil {
		return err
	}
	defer pemFile.Close()

	roots := x509.NewCertPool()

	for _, path := range paths {
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		certs, err := x509.ParseCertificates(bytes)
		if err != nil {
			var cert *x509.Certificate
			for len(bytes) > 0 {
				var block *pem.Block
				block, bytes = pem.Decode(bytes)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
					continue
				}
				cert, err = x509.ParseCertificate(block.Bytes)
				if err == nil {
					certs = append(certs, cert)
				}
			}
		}
		if err != nil {
			return newError("failed to parse certificate ", path).Base(err)
		}
		for _, cert := range certs {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			if err := pem.Encode(pemFile, block); err != nil {
				return err
			}
			roots.AddCert(cert)
		}
	}

	systemRoots = roots
	return nil
}
