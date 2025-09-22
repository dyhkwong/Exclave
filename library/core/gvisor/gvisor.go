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
	"os"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"libcore/tun"
)

//go:generate go run ../errorgen

var _ tun.Tun = (*GVisor)(nil)

type GVisor struct {
	Endpoint stack.LinkEndpoint
	PcapFile *os.File
	Stack    *stack.Stack
}

func (t *GVisor) Close() error {
	t.Stack.Close()
	if t.PcapFile != nil {
		_ = t.PcapFile.Close()
	}
	return nil
}

const DefaultNIC tcpip.NICID = 0x01

func New(dev int32, mtu int32, handler tun.Handler, nicId tcpip.NICID, pcap bool, pcapFile *os.File, snapLen uint32, enableIPv6 bool) (*GVisor, error) {
	var endpoint stack.LinkEndpoint
	endpoint, _ = newRwEndpoint(dev, mtu)
	if pcap {
		pcapEndpoint, err := sniffer.NewWithWriter(endpoint, &pcapFileWrapper{pcapFile}, snapLen)
		if err != nil {
			return nil, err
		}
		endpoint = pcapEndpoint
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
			NIC:         nicId,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicId,
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
	gMust(s.CreateNIC(nicId, endpoint))
	gMust(s.SetSpoofing(nicId, true))
	gMust(s.SetPromiscuousMode(nicId, true))

	return &GVisor{endpoint, pcapFile, s}, nil
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

func gMust(err tcpip.Error) {
	if err != nil {
		newError(err).AtError().WriteToLog()
	}
}

func tcpipErr(err tcpip.Error) error {
	return newError(err.String())
}
