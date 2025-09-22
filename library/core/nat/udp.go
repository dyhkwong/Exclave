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

package nat

import (
	"github.com/v2fly/v2ray-core/v5/common/buf"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (t *SystemTun) processIPv4UDP(cache *buf.Buffer, ipHdr header.IPv4, hdr header.UDP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := hdr.SourcePort()
	destinationPort := hdr.DestinationPort()

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(sourceAddress.AsSlice()),
		Port:    v2rayNet.Port(sourcePort),
		Network: v2rayNet.Network_UDP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(destinationAddress.AsSlice()),
		Port:    v2rayNet.Port(destinationPort),
		Network: v2rayNet.Network_UDP,
	}

	ipHdr.SetDestinationAddress(sourceAddress)
	hdr.SetDestinationPort(sourcePort)

	ipHdrLength := ipHdr.HeaderLength()
	newHeader := make([]byte, ipHdrLength+header.UDPMinimumSize)
	copy(newHeader, ipHdr[:ipHdrLength+header.UDPMinimumSize])

	cache.Advance(int32(ipHdrLength + header.UDPMinimumSize))
	go t.handler.NewPacket(source, destination, cache, func(bytes []byte, addr *v2rayNet.UDPAddr) (int, error) {
		var newSourceAddress tcpip.Address
		var newSourcePort uint16

		if addr != nil {
			newSourceAddress = tcpip.AddrFromSlice(addr.IP)
			newSourcePort = uint16(addr.Port)
		} else {
			newSourceAddress = destinationAddress
			newSourcePort = destinationPort
		}

		newIpHdr := header.IPv4(newHeader)
		newIpHdr.SetSourceAddress(newSourceAddress)
		newIpHdr.SetTotalLength(uint16(int(ipHdrLength+header.UDPMinimumSize) + len(bytes)))
		newIpHdr.SetChecksum(0)
		newIpHdr.SetChecksum(^newIpHdr.CalculateChecksum())

		udpHdr := header.UDP(newHeader[ipHdrLength:])
		udpHdr.SetSourcePort(newSourcePort)
		udpHdr.SetLength(uint16(header.UDPMinimumSize + len(bytes)))
		udpHdr.SetChecksum(0)
		udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(bytes, header.PseudoHeaderChecksum(header.UDPProtocolNumber, newSourceAddress, sourceAddress, uint16(header.UDPMinimumSize+len(bytes))))))

		payload := buffer.MakeWithData(newHeader)
		payload.Append(buffer.NewViewWithData(bytes))

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload,
		})
		if err := t.writeRawPacket(pkt); err != nil {
			return 0, newError(err.String())
		}

		return len(bytes), nil
	})
}

func (t *SystemTun) processIPv6UDP(cache *buf.Buffer, ipHdr header.IPv6, hdr header.UDP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := hdr.SourcePort()
	destinationPort := hdr.DestinationPort()

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(sourceAddress.AsSlice()),
		Port:    v2rayNet.Port(sourcePort),
		Network: v2rayNet.Network_UDP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(destinationAddress.AsSlice()),
		Port:    v2rayNet.Port(destinationPort),
		Network: v2rayNet.Network_UDP,
	}

	ipHdr.SetDestinationAddress(sourceAddress)
	hdr.SetDestinationPort(sourcePort)

	ipHdrLength := uint16(len(ipHdr)) - ipHdr.PayloadLength()
	newHeader := make([]byte, ipHdrLength+header.UDPMinimumSize)
	copy(newHeader, ipHdr[:ipHdrLength+header.UDPMinimumSize])

	cache.Advance(int32(ipHdrLength + header.UDPMinimumSize))
	go t.handler.NewPacket(source, destination, cache, func(bytes []byte, addr *v2rayNet.UDPAddr) (int, error) {
		var newSourceAddress tcpip.Address
		var newSourcePort uint16

		if addr != nil {
			newSourceAddress = tcpip.AddrFromSlice(addr.IP)
			newSourcePort = uint16(addr.Port)
		} else {
			newSourceAddress = destinationAddress
			newSourcePort = destinationPort
		}

		newIpHdr := header.IPv6(newHeader)
		newIpHdr.SetSourceAddress(newSourceAddress)
		newIpHdr.SetPayloadLength(uint16(header.UDPMinimumSize + len(bytes)))

		udpHdr := header.UDP(newHeader[ipHdrLength:])
		udpHdr.SetSourcePort(newSourcePort)
		udpHdr.SetLength(uint16(header.UDPMinimumSize + len(bytes)))
		udpHdr.SetChecksum(0)
		udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(bytes, header.PseudoHeaderChecksum(header.UDPProtocolNumber, newSourceAddress, sourceAddress, uint16(header.UDPMinimumSize+len(bytes))))))

		payload := buffer.MakeWithData(newHeader)
		payload.Append(buffer.NewViewWithData(bytes))

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload,
		})
		if err := t.writeRawPacket(pkt); err != nil {
			return 0, newError(err.String())
		}

		return len(bytes), nil
	})
}
