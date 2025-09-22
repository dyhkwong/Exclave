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
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func (t *SystemTun) processICMPv4(ipHdr header.IPv4, hdr header.ICMPv4) {
	if hdr.Type() != header.ICMPv4Echo || hdr.Code() != header.ICMPv4UnusedCode {
		return
	}

	sourceAddress := ipHdr.SourceAddress()
	ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
	ipHdr.SetDestinationAddress(sourceAddress)
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	hdr.SetType(header.ICMPv4EchoReply)
	hdr.SetChecksum(0)
	hdr.SetChecksum(header.ICMPv4Checksum(hdr, 0))
	t.writeBuffer(ipHdr)
}

func (t *SystemTun) processICMPv6(ipHdr header.IPv6, hdr header.ICMPv6) {
	if hdr.Type() != header.ICMPv6EchoRequest || hdr.Code() != header.ICMPv6UnusedCode {
		return
	}

	sourceAddress := ipHdr.SourceAddress()
	ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
	ipHdr.SetDestinationAddress(sourceAddress)

	hdr.SetType(header.ICMPv6EchoReply)
	hdr.SetChecksum(0)
	hdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: hdr,
		Src:    ipHdr.SourceAddress(),
		Dst:    ipHdr.DestinationAddress(),
	}))
	t.writeBuffer(ipHdr)
}
