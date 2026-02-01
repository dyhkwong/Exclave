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
	_ stack.LinkEndpoint      = (*icmpDiscardedLinkEndpoint)(nil)
	_ stack.NetworkDispatcher = (*icmpDiscardedLinkEndpoint)(nil)
)

// icmpDiscardedLinkEndpoint workarounds https://github.com/google/gvisor/issues/8657
type icmpDiscardedLinkEndpoint struct {
	stack.LinkEndpoint
	dispatcher stack.NetworkDispatcher
}

func (e *icmpDiscardedLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	e.LinkEndpoint.Attach(e)
}

func (e *icmpDiscardedLinkEndpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	switch protocol {
	case header.IPv4ProtocolNumber:
		if hdr := header.IPv4(pkt.Data().AsRange().ToSlice()); hdr.TransportProtocol() == header.ICMPv4ProtocolNumber {
			return
		}
	case header.IPv6ProtocolNumber:
		if hdr := header.IPv6(pkt.Data().AsRange().ToSlice()); hdr.TransportProtocol() == header.ICMPv6ProtocolNumber {
			return
		}
	}
	e.dispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (e *icmpDiscardedLinkEndpoint) DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	panic("unimplemented")
}
