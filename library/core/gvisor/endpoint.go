/*
Copyright (C) 2026  dyhkwong

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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	_ stack.LinkEndpoint      = (*linkEndpointWithDiscard)(nil)
	_ stack.NetworkDispatcher = (*linkEndpointWithDiscard)(nil)
)

type linkEndpointWithDiscard struct {
	stack.LinkEndpoint
	dispatcher  stack.NetworkDispatcher
	discardIPv6 func() bool
	discardICMP bool // see https://github.com/google/gvisor/issues/8657
}

func (e *linkEndpointWithDiscard) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	e.LinkEndpoint.Attach(e)
}

func (e *linkEndpointWithDiscard) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	dispatcher := e.dispatcher
	if dispatcher == nil {
		return
	}
	packet := pkt.Data().AsRange().ToSlice()
	switch protocol {
	case header.IPv4ProtocolNumber:
		if e.discardICMP {
			hdr := header.IPv4(packet)
			if hdr.TransportProtocol() == header.ICMPv4ProtocolNumber {
				newError("discarded ICMP to ", hdr.DestinationAddress()).AtDebug().WriteToLog()
				return
			}
		}
	case header.IPv6ProtocolNumber:
		discardIPv6 := false
		if e.discardIPv6 != nil {
			discardIPv6 = e.discardIPv6()
		}
		if e.discardICMP || discardIPv6 {
			hdr := header.IPv6(packet)
			if e.discardICMP && hdr.TransportProtocol() == header.ICMPv4ProtocolNumber {
				newError("discarded ICMPv6 to ", hdr.DestinationAddress()).AtDebug().WriteToLog()
				return
			}
			if discardIPv6 {
				newError("discarded IPv6 to ", hdr.DestinationAddress()).AtDebug().WriteToLog()
				return
			}
		}
	}
	dispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (e *linkEndpointWithDiscard) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	panic("unimplemented")
}
