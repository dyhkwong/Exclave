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

package gvisor

import (
	"io"
	"math"
	"os"

	"libcore/tun"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

//go:generate go run ../errorgen

var _ tun.Tun = (*GVisor)(nil)

type GVisor struct {
	endpoint stack.LinkEndpoint
	stack    *stack.Stack
	pcapFile *os.File
}

func (t *GVisor) Close() error {
	t.endpoint.Close()
	t.stack.Close()
	if t.pcapFile != nil {
		_ = t.pcapFile.Close()
	}
	return nil
}

const DefaultNIC tcpip.NICID = 0x01

func New(dev int32, mtu int32, handler tun.Handler, pcapFile *os.File, enableIPv6 bool) (*GVisor, error) {
	var endpoint stack.LinkEndpoint
	var err error
	endpoint, err = fdbased.New(&fdbased.Options{
		FDs:               []int{int(dev)},
		MTU:               uint32(mtu),
		RXChecksumOffload: true,
	})
	if err != nil {
		return nil, err
	}
	if pcapFile != nil {
		endpoint, err = sniffer.NewWithWriter(endpoint, &pcapFileWrapper{pcapFile}, math.MaxUint32)
		if err != nil {
			return nil, err
		}
	}
	var o stack.Options
	if enableIPv6 {
		o = stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
				icmp.NewProtocol6,
			},
		}
	} else {
		o = stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
			},
		}
	}
	s := stack.New(o)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         DefaultNIC,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         DefaultNIC,
		},
	})

	bufSize := buf.Size
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})

	sOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)

	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)

	gTcpHandler(s, handler)
	gUdpHandler(s, handler)
	// Uncomment if we have to upgrade gvisor one day.
	/*s.SetTransportProtocolHandler(icmp.ProtocolNumber4, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		// workaround https://github.com/google/gvisor/commit/868dfbce4fd59f03145e2bc5ac0b585917c371fa
		// This change makes it impossible to restore the old promiscuous mode behavior without reimplementing ICMP in a custom handler.
		hdr := header.ICMPv4(pkt.TransportHeader().Slice())
		if hdr.Type() != header.ICMPv4Echo {
			return false
		}
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		hdr.SetType(header.ICMPv4EchoReply)
		hdr.SetChecksum(0)
		hdr.SetChecksum(header.ICMPv4Checksum(hdr, pkt.Data().Checksum()))
		var pkts stack.PacketBufferList
		pkts.PushBack(pkt)
		_, err := endpoint.WritePackets(pkts)
		if err != nil {
			return false
		}
		return true
	})*/
	if tcpipErr := s.CreateNIC(DefaultNIC, endpoint); tcpipErr != nil {
		return nil, newError(tcpipErr)
	}
	if tcpipErr := s.SetSpoofing(DefaultNIC, true); tcpipErr != nil {
		return nil, newError(tcpipErr)
	}
	if tcpipErr := s.SetPromiscuousMode(DefaultNIC, true); tcpipErr != nil {
		return nil, newError(tcpipErr)
	}
	return &GVisor{
		endpoint: endpoint,
		stack:    s,
		pcapFile: pcapFile,
	}, nil
}

type pcapFileWrapper struct {
	io.Writer
}

func (w *pcapFileWrapper) Write(p []byte) (n int, err error) {
	n, err = w.Writer.Write(p)
	if err != nil {
		newError("write pcap file failed").Base(err).AtDebug().WriteToLog()
	}
	return n, err
}
