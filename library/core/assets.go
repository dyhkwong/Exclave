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
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/sagernet/gomobile/asset"
	"github.com/v2fly/v2ray-core/v5/common/platform/filesystem"
)

const (
	mozillaIncludedPem = "mozilla_included.pem"
	androidIncludedPem = "android_included.pem"
	customPem          = "root_store.certs"
)

var (
	assetsAccess       sync.Mutex
	assetsPrefix       string
	internalAssetsPath string
	externalAssetsPath string
)

func InitializeV2Ray(internalAssets string, externalAssets string, prefix string, caProvider int32) error {
	assetsPrefix = prefix
	internalAssetsPath = internalAssets
	externalAssetsPath = externalAssets

	fileSeeker := func(path string) (io.ReadSeekCloser, error) {
		_, fileName := filepath.Split(path)
		if _, err := os.Stat(externalAssetsPath + fileName); err == nil {
			return os.Open(externalAssetsPath + fileName)
		}
		if _, err := os.Stat(internalAssetsPath + fileName); err == nil {
			return os.Open(internalAssetsPath + fileName)
		}
		if file, err := asset.Open(assetsPrefix + fileName); err == nil {
			return file, nil
		}
		return nil, newError("asset ", fileName, " not found")
	}

	filesystem.NewFileSeeker = fileSeeker

	filesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		return fileSeeker(path)
	}

	err := updateSystemRoots(caProvider)

	return err
}

func extractMozillaCAPem() error {
	path := internalAssetsPath + mozillaIncludedPem
	sumPath := path + ".sha256sum"
	sumInternal, err := asset.Open(mozillaIncludedPem + ".sha256sum")
	if err != nil {
		return newError("open pem version in assets").Base(err)
	}
	defer sumInternal.Close()
	sumBytes, err := io.ReadAll(sumInternal)
	if err != nil {
		return newError("read internal version").Base(err)
	}
	_, pemSha256sumNotExists := os.Stat(sumPath)
	if pemSha256sumNotExists == nil {
		sumExternal, err := os.ReadFile(sumPath)
		if err == nil {
			if string(sumBytes) == string(sumExternal) {
				return nil
			}
		}
	}
	pemFile, err := os.Create(path)
	if err != nil {
		return newError("create pem file").Base(err)
	}
	defer pemFile.Close()
	pem, err := asset.Open(mozillaIncludedPem)
	if err != nil {
		return newError("open pem in assets").Base(err)
	}
	defer pem.Close()
	_, err = io.Copy(pemFile, pem)
	if err != nil {
		return newError("write pem file")
	}
	return os.WriteFile(sumPath, sumBytes, 0o644)
}
