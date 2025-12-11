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
	"context"
	"net"
	"net/netip"
	"strconv"

	"github.com/ccding/go-stun/stun"
	"github.com/wzshiming/socks5"
)

func setupStunClient(useSOCKS5 bool, serverAddress string, socksPort, dnsPort int32) (*stun.Client, error) {
	if useSOCKS5 {
		addr, port, err := net.SplitHostPort(serverAddress)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(addr); err != nil {
			if dnsPort <= 0 {
				return nil, newError("server address is a domain name, but DNS inbound is disabled")
			}
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					dialer := new(net.Dialer)
					return dialer.DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(int(dnsPort)))
				},
			}
			ips, err := resolver.LookupIP(context.Background(), "ip", addr)
			if err != nil {
				return nil, err
			}
			serverAddress = net.JoinHostPort(ips[0].String(), port)
		}
		dialer, _ := socks5.NewDialer("socks5h://127.0.0.1:" + strconv.Itoa(int(socksPort)))
		conn, err := dialer.Dial("udp", serverAddress)
		if err != nil {
			return nil, err
		}
		client := stun.NewClientWithConnection(conn.(*socks5.UDPConn))
		client.SetServerAddr(serverAddress)
		return client, nil
	} else {
		client := stun.NewClient()
		client.SetServerAddr(serverAddress)
		return client, nil
	}
}

type StunResult struct {
	NatMapping   string
	NatFiltering string
	Error        string
}

// RFC 5780
func StunTest(serverAddress string, useSOCKS5 bool, socksPort, dnsPort int32) *StunResult {
	result := new(StunResult)
	client, err := setupStunClient(useSOCKS5, serverAddress, socksPort, dnsPort)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	natBehavior, err := client.BehaviorTest()
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

// RFC 3489
func StunLegacyTest(serverAddress string, useSOCKS5 bool, socksPort, dnsPort int32) *StunLegacyResult {
	result := new(StunLegacyResult)
	client, err := setupStunClient(useSOCKS5, serverAddress, socksPort, dnsPort)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	natType, host, err := client.Discover()
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
