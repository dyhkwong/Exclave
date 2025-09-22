/*
Copyright (c) 2024 HystericalDragon <HystericalDragons@proton.me>

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
	"os"

	"github.com/v2fly/v2ray-core/v5/common/errors"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"golang.org/x/sys/unix"
)

var (
	_ internet.SystemDialer = (*protectedDialer)(nil)
)

type Protector interface {
	Protect(fd int32) bool
}

type noopProtector struct{}

func (n *noopProtector) Protect(int32) bool {
	return true
}

type protectedDialer struct {
	protector Protector
	resolver  func(domain string) ([]net.IP, error)
}

func (dialer protectedDialer) Dial(ctx context.Context, src v2rayNet.Address, dest v2rayNet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	if dest.Network == v2rayNet.Network_Unknown || dest.Network == v2rayNet.Network_UNIX || dest.Address == nil {
		return nil, newError("invalid destination")
	}
	var ips []net.IP
	if dest.Address.Family().IsDomain() {
		var err error
		ips, err = dialer.resolver(dest.Address.Domain())
		if err == nil && len(ips) == 0 {
			err = dns.ErrEmptyResponse
		}
		if err != nil {
			return nil, err
		}
	} else {
		ips = append(ips, dest.Address.IP())
	}
	errs := []error{}
	for _, ip := range ips {
		dest.Address = v2rayNet.IPAddress(ip)
		if conn, err := dialer.dial(ctx, src, dest, sockopt); err == nil {
			return conn, nil
		} else {
			errs = append(errs, err)
		}
	}
	return nil, newError(errors.Combine(errs...))
}

func (dialer protectedDialer) dial(ctx context.Context, src v2rayNet.Address, dest v2rayNet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	var fd int
	var err error
	switch {
	case dest.Network == v2rayNet.Network_UDP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	case dest.Address.Family().IsIPv4():
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	default:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	}
	if err != nil {
		return nil, err
	}
	if !dialer.protector.Protect(int32(fd)) {
		unix.Close(fd)
		return nil, newError("protect failed")
	}
	if sockopt != nil {
		var network string
		switch dest.Network {
		case v2rayNet.Network_TCP:
			switch dest.Address.Family() {
			case v2rayNet.AddressFamilyIPv4:
				network = "tcp4"
			case v2rayNet.AddressFamilyIPv6:
				network = "tcp6"
			}
			internet.ApplySockopt(network, dest.NetAddr(), uintptr(fd), sockopt)
		case v2rayNet.Network_UDP:
			if src == nil || src == v2rayNet.AnyIP || src == v2rayNet.AnyIPv6 {
				src = v2rayNet.AnyIPv6
			}
			switch src.Family() {
			case v2rayNet.AddressFamilyIPv4:
				network = "udp4"
			case v2rayNet.AddressFamilyIPv6:
				network = "udp6"
			}
			internet.ApplySockopt(network, net.JoinHostPort(src.IP().String(), "0"), uintptr(fd), sockopt)
		}
	}
	switch dest.Network {
	case v2rayNet.Network_TCP:
		var sockaddr unix.Sockaddr
		if dest.Address.Family().IsIPv4() {
			sockaddrInet4 := &unix.SockaddrInet4{
				Port: int(dest.Port),
			}
			copy(sockaddrInet4.Addr[:], dest.Address.IP())
			sockaddr = sockaddrInet4
		} else {
			sockaddrInet6 := &unix.SockaddrInet6{
				Port: int(dest.Port),
			}
			copy(sockaddrInet6.Addr[:], dest.Address.IP())
			sockaddr = sockaddrInet6
		}
		err = unix.Connect(fd, sockaddr)
	case v2rayNet.Network_UDP:
		err = unix.Bind(fd, &unix.SockaddrInet6{})
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "socket")
	if file == nil {
		unix.Close(fd)
		return nil, newError("failed to connect to fd")
	}
	defer file.Close()

	switch dest.Network {
	case v2rayNet.Network_UDP:
		packetConn, err := net.FilePacketConn(file)
		if err != nil {
			unix.Close(fd)
			return nil, err
		}
		destAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
		if err != nil {
			unix.Close(fd)
			return nil, err
		}
		return &internet.PacketConnWrapper{
			Conn: packetConn,
			Dest: destAddr,
		}, nil
	default:
		conn, err := net.FileConn(file)
		if err != nil {
			unix.Close(fd)
			return nil, err
		}
		return conn, nil
	}
}
