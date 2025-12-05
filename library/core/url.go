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
	"net"
	"net/url"
	"strconv"
	_ "unsafe"
)

type URL interface {
	GetScheme() string
	SetScheme(scheme string)
	GetOpaque() string
	SetOpaque(opaque string)
	GetUsername() string
	SetUsername(username string)
	GetPassword() string
	SetPassword(password string) error
	GetHost() string
	SetHost(host string)
	GetPort() int32
	SetPort(port int32)
	GetPath() string
	SetPath(path string)
	GetRawPath() string
	SetRawPath(rawPath string) error
	GetRawQuery() string
	SetRawQuery(rawPath string)
	HasQueryParameter(key string) bool
	CountQueryParameter(key string) int
	GetQueryParameter(key string) string
	GetQueryParameterAt(key string, i int) string
	AddQueryParameter(key, value string)
	DeleteQueryParameter(key string)
	GetFragment() string
	SetFragment(fragment string)
	GetRawFragment() string
	SetRawFragment(rawFragment string) error
	GetString() string
}

var _ URL = (*netURL)(nil)

type netURL struct {
	*url.URL
}

func NewURL(scheme string) URL {
	return &netURL{
		URL: &url.URL{
			Scheme: scheme,
		},
	}
}

//go:linkname setFragment net/url.(*URL).setFragment
func setFragment(u *url.URL, fragment string) error

//go:linkname setPath net/url.(*URL).setPath
func setPath(u *url.URL, fragment string) error

func ParseURL(rawURL string) (URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return &netURL{URL: u}, nil
}

func (u *netURL) GetScheme() string {
	return u.Scheme
}

func (u *netURL) SetScheme(scheme string) {
	u.Scheme = scheme
}

func (u *netURL) GetOpaque() string {
	return u.Opaque
}

func (u *netURL) SetOpaque(opaque string) {
	u.Opaque = opaque
}

func (u *netURL) GetUsername() string {
	if u.User != nil {
		return u.User.Username()
	}
	return ""
}

func (u *netURL) SetUsername(username string) {
	if u.User != nil {
		if password, ok := u.User.Password(); !ok {
			u.User = url.User(username)
		} else {
			u.User = url.UserPassword(username, password)
		}
	} else {
		u.User = url.User(username)
	}
}

func (u *netURL) GetPassword() string {
	if u.User != nil {
		if password, ok := u.User.Password(); ok {
			return password
		}
	}
	return ""
}

func (u *netURL) SetPassword(password string) error {
	if u.User == nil {
		return newError("set username first")
	}
	u.User = url.UserPassword(u.User.Username(), password)
	return nil
}

func (u *netURL) GetHost() string {
	return u.Hostname()
}

func (u *netURL) SetHost(host string) {
	_, port, err := net.SplitHostPort(u.Host)
	if err == nil {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
}

func (u *netURL) GetPort() int32 {
	portStr := u.Port()
	if portStr == "" {
		return 0
	}
	port, _ := strconv.Atoi(portStr)
	return int32(port)
}

func (u *netURL) SetPort(port int32) {
	host, _, err := net.SplitHostPort(u.Host)
	if err == nil {
		u.Host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	} else {
		u.Host = net.JoinHostPort(u.Host, strconv.Itoa(int(port)))
	}
}

func (u *netURL) GetPath() string {
	return u.Path
}

func (u *netURL) SetPath(path string) {
	u.Path = path
	u.RawPath = ""
}

func (u *netURL) GetRawPath() string {
	if len(u.RawPath) > 0 {
		return u.RawPath
	}
	return u.Path
}

func (u *netURL) SetRawPath(rawPath string) error {
	return setPath(u.URL, rawPath)
}

func (u *netURL) GetRawQuery() string {
	return u.RawQuery
}

func (u *netURL) SetRawQuery(rawQuery string) {
	u.RawQuery = rawQuery
}

func (u *netURL) HasQueryParameter(key string) bool {
	return u.Query().Has(key)
}

func (u *netURL) GetQueryParameter(key string) string {
	return u.Query().Get(key)
}

func (u *netURL) CountQueryParameter(key string) int {
	queries := u.Query()
	v, ok := queries[key]
	if !ok {
		return 0
	}
	return len(v)
}

func (u *netURL) GetQueryParameterAt(key string, i int) string {
	queries := u.Query()
	v, ok := queries[key]
	if !ok {
		return ""
	}
	if i < 0 || i >= len(v) {
		return ""
	}
	return v[i]
}

func (u *netURL) AddQueryParameter(key, value string) {
	queries := u.Query()
	queries.Add(key, value)
	u.RawQuery = queries.Encode()
}

func (u *netURL) DeleteQueryParameter(key string) {
	queries := u.Query()
	queries.Del(key)
	u.RawQuery = queries.Encode()
}

func (u *netURL) SetFragment(fragment string) {
	u.Fragment = fragment
	u.RawFragment = ""
}

func (u *netURL) GetFragment() string {
	return u.Fragment
}

func (u *netURL) SetRawFragment(rawFragment string) error {
	return setFragment(u.URL, rawFragment)
}

func (u *netURL) GetRawFragment() string {
	if len(u.RawFragment) > 0 {
		return u.RawFragment
	}
	return u.Fragment
}

func (u *netURL) GetString() string {
	return u.String()
}
