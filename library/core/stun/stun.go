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

package stun

import (
	"net"
	"strconv"

	"github.com/ccding/go-stun/stun"
	"github.com/wzshiming/socks5"
)

func setupPacketConn(useSOCKS5 bool, addrStr string, socksPort int) (net.PacketConn, error) {
	if useSOCKS5 {
		dialer, _ := socks5.NewDialer("socks5h://127.0.0.1:" + strconv.Itoa(socksPort))
		conn, err := dialer.Dial("udp", addrStr)
		if err != nil {
			return nil, err
		}
		return conn.(*socks5.UDPConn), nil
	} else {
		return net.ListenUDP("udp", nil)
	}
}

// RFC 5780
func Test(addrStr string, useSOCKS5 bool, socksPort int) (*stun.NATBehavior, error) {
	packetConn, err := setupPacketConn(useSOCKS5, addrStr, socksPort)
	if err != nil {
		return nil, err
	}
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(addrStr)
	return client.BehaviorTest()
}

// RFC 3489
func TestLegacy(addrStr string, useSOCKS5 bool, socksPort int) (stun.NATType, *stun.Host, error) {
	packetConn, err := setupPacketConn(useSOCKS5, addrStr, socksPort)
	if err != nil {
		return 0, nil, err
	}
	client := stun.NewClientWithConnection(packetConn)
	client.SetServerAddr(addrStr)
	return client.Discover()
}
