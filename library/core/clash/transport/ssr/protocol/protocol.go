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

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
)

var (
	errAuthSHA1V4CRC32Error   = errors.New("auth_sha1_v4 decode data wrong crc32")
	errAuthSHA1V4LengthError  = errors.New("auth_sha1_v4 decode data wrong length")
	errAuthSHA1V4Adler32Error = errors.New("auth_sha1_v4 decode data wrong adler32")
	errAuthAES128MACError     = errors.New("auth_aes128 decode data wrong mac")
	errAuthAES128LengthError  = errors.New("auth_aes128 decode data wrong length")
	errAuthAES128ChksumError  = errors.New("auth_aes128 decode data wrong checksum")
	errAuthChainLengthError   = errors.New("auth_chain decode data wrong length")
	errAuthChainChksumError   = errors.New("auth_chain decode data wrong checksum")
)

type Protocol interface {
	StreamConn(net.Conn, []byte) net.Conn
	PacketConn(net.PacketConn) net.PacketConn
	Decode(dst, src *bytes.Buffer) error
	Encode(buf *bytes.Buffer, b []byte) error
	DecodePacket([]byte) ([]byte, error)
	EncodePacket(buf *bytes.Buffer, b []byte) error
}

type protocolCreator func(b *Base) Protocol

var protocolList = make(map[string]struct {
	overhead int
	new      protocolCreator
})

func register(name string, c protocolCreator, o int) {
	protocolList[name] = struct {
		overhead int
		new      protocolCreator
	}{overhead: o, new: c}
}

func PickProtocol(name string, b *Base) (Protocol, error) {
	if choice, ok := protocolList[name]; ok {
		b.Overhead += choice.overhead
		return choice.new(b), nil
	}
	return nil, fmt.Errorf("protocol %s not supported", name)
}

func getHeadSize(b []byte, defaultValue int) int {
	if len(b) < 2 {
		return defaultValue
	}
	headType := b[0] & 7
	switch headType {
	case 1:
		return 7
	case 4:
		return 19
	case 3:
		return 4 + int(b[1])
	}
	return defaultValue
}

func getDataLength(b []byte) int {
	bLength := len(b)
	dataLength := getHeadSize(b, 30) + rand.Intn(32)
	if bLength < dataLength {
		return bLength
	}
	return dataLength
}
