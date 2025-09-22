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
	"net"
)

type origin struct{}

func init() { register("origin", newOrigin, 0) }

func newOrigin(b *Base) Protocol { return &origin{} }

func (o *origin) StreamConn(c net.Conn, iv []byte) net.Conn { return c }

func (o *origin) PacketConn(c net.PacketConn) net.PacketConn { return c }

func (o *origin) Decode(dst, src *bytes.Buffer) error {
	dst.ReadFrom(src)
	return nil
}

func (o *origin) Encode(buf *bytes.Buffer, b []byte) error {
	buf.Write(b)
	return nil
}

func (o *origin) DecodePacket(b []byte) ([]byte, error) { return b, nil }

func (o *origin) EncodePacket(buf *bytes.Buffer, b []byte) error {
	buf.Write(b)
	return nil
}
