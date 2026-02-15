//go:build !go1.26

/*
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// modified from https://github.com/golang/go/blob/c6f882f6c58ed56fa4bd2d8256ec55d9992c3583/src/crypto/x509/x509_string.go

package libcore

import (
	"crypto/x509"
	"strconv"
)

const (
	_KeyUsage_name_0  = "digitalSignaturecontentCommitment"
	_KeyUsage_name_1  = "keyEncipherment"
	_KeyUsage_name_2  = "dataEncipherment"
	_KeyUsage_name_3  = "keyAgreement"
	_KeyUsage_name_4  = "keyCertSign"
	_KeyUsage_name_5  = "cRLSign"
	_KeyUsage_name_6  = "encipherOnly"
	_KeyUsage_name_7  = "decipherOnly"
	_ExtKeyUsage_name = "anyExtendedKeyUsageserverAuthclientAuthcodeSigningemailProtectionipsecEndSystemipsecTunnelipsecUsertimeStampingOCSPSigningmsSGCnsSGCmsCodeCommsKernelCode"
)

var (
	_KeyUsage_index_0  = [...]uint8{0, 16, 33}
	_ExtKeyUsage_index = [...]uint8{0, 19, 29, 39, 50, 65, 79, 90, 99, 111, 122, 127, 132, 141, 153}
)

func keyUsageToString(i x509.KeyUsage) string {
	switch {
	case 1 <= i && i <= 2:
		i -= 1
		return _KeyUsage_name_0[_KeyUsage_index_0[i]:_KeyUsage_index_0[i+1]]
	case i == 4:
		return _KeyUsage_name_1
	case i == 8:
		return _KeyUsage_name_2
	case i == 16:
		return _KeyUsage_name_3
	case i == 32:
		return _KeyUsage_name_4
	case i == 64:
		return _KeyUsage_name_5
	case i == 128:
		return _KeyUsage_name_6
	case i == 256:
		return _KeyUsage_name_7
	default:
		return "KeyUsage(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}

func extKeyUsageToString(i x509.ExtKeyUsage) string {
	idx := int(i) - 0
	if i < 0 || idx >= len(_ExtKeyUsage_index)-1 {
		return "ExtKeyUsage(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _ExtKeyUsage_name[_ExtKeyUsage_index[idx]:_ExtKeyUsage_index[idx+1]]
}
