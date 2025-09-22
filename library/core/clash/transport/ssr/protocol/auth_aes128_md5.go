/*
Copyright (C) 2021 by clash authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package protocol

import "libcore/clash/transport/ssr/tools"

func init() {
	register("auth_aes128_md5", newAuthAES128MD5, 9)
}

func newAuthAES128MD5(b *Base) Protocol {
	a := &authAES128{
		Base:               b,
		authData:           &authData{},
		authAES128Function: &authAES128Function{salt: "auth_aes128_md5", hmac: tools.HmacMD5, hashDigest: tools.MD5Sum},
		userData:           &userData{},
	}
	a.initUserData()
	return a
}
