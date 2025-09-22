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
	"os"

	"libcore/stun"
)

//go:generate go run ./errorgen

func Setenv(key, value string) error {
	return os.Setenv(key, value)
}

func Unsetenv(key string) error {
	return os.Unsetenv(key)
}

type StunResult struct {
	NatMapping   string
	NatFiltering string
	Error        string
}

func StunTest(serverAddress string, useSOCKS5 bool, socksPort int32) *StunResult {
	result := new(StunResult)
	natBehavior, err := stun.Test(serverAddress, useSOCKS5, int(socksPort))
	if err != nil {
		result.Error = err.Error()
	}
	if natBehavior != nil {
		result.NatMapping = natBehavior.MappingType.String()
		result.NatFiltering = natBehavior.FilteringType.String()
	}
	return result
}

type StunLegacyResult struct {
	NatType string
	Host    string
	Error   string
}

func StunLegacyTest(serverAddress string, useSOCKS5 bool, socksPort int32) *StunLegacyResult {
	result := new(StunLegacyResult)
	natType, host, err := stun.TestLegacy(serverAddress, useSOCKS5, int(socksPort))
	if err != nil {
		result.Error = err.Error()
	}
	if host != nil {
		result.Host = host.String()
	}
	if natType > 0 {
		result.NatType = natType.String()
	}
	return result
}
