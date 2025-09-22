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

const (
	caProviderMozilla = iota
	caProviderSystem
	caProviderSystemAndUser // for https://github.com/golang/go/issues/71258
)

//go:linkname systemRoots crypto/x509.systemRoots
var systemRoots *x509.CertPool

func setupMozillaCAProvider() error {
	if err := extractMozillaCAPem(); err != nil {
		return err
	}
	pemPath := externalAssetsPath + mozillaIncludedPem
	pemFile, err := os.ReadFile(pemPath)
	if err != nil {
		pemPath = internalAssetsPath + mozillaIncludedPem
		pemFile, err = os.ReadFile(pemPath)
	}
	if err != nil {
		return err
	}
	newError("load ", mozillaIncludedPem, " from ", pemPath).AtInfo().WriteToLog()
	x509.SystemCertPool()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemFile) {
		return newError("failed to append certificates from pem")
	}
	systemRoots = roots
	return nil
}

func UpdateSystemRoots(caProvider int32) {
	assetsAccess.Lock()
	defer assetsAccess.Unlock()
	switch caProvider {
	case caProviderSystem:
		systemRoots, _ = x509.SystemCertPool()
		newError("using system CA provider").AtInfo().WriteToLog()
	case caProviderMozilla:
		if err := setupMozillaCAProvider(); err != nil {
			newError(err).AtError().WriteToLog()
			return
		}
		newError("using Mozilla CA provider").AtInfo().WriteToLog()
	case caProviderSystemAndUser:
		if err := setupSystemAndUserCAProvider(); err != nil {
			newError(err).AtError().WriteToLog()
			return
		}
		newError("using system and user CA provider").AtInfo().WriteToLog()
	}
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

	pemFile, err := os.Create(internalAssetsPath + androidIncludedPem) // for plugins
	if err != nil {
		return err
	}
	defer pemFile.Close()

	x509.SystemCertPool()
	roots := x509.NewCertPool()

	for _, path := range paths {
		bytes, err := os.ReadFile(path)
		if err != nil {
			newError("failed to read certificate ", path).Base(err).AtError().WriteToLog()
			continue
		}
		certs, parseErr := x509.ParseCertificates(bytes)
		if parseErr != nil {
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
				if cert, parseErr = x509.ParseCertificate(block.Bytes); parseErr == nil {
					certs = append(certs, cert)
				}
			}
		}
		if parseErr != nil {
			newError("failed to parse certificate ", path).AtError().WriteToLog()
			continue
		}
		for _, cert := range certs {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			if err := pem.Encode(pemFile, block); err != nil {
				newError("failed to encode certificate ", path).AtError().WriteToLog()
				continue
			}
			roots.AddCert(cert)
		}
	}
	systemRoots = roots
	return nil
}
