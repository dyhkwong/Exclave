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
	"net"
	"time"

	"libcore/common"

	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type tcpForwarder struct {
	tun       *SystemTun
	port4     uint16
	port6     uint16
	listener4 *net.TCPListener
	listener6 *net.TCPListener
	sessions  *common.LruCache
	closed    bool
}

func newTcpForwarder(tun *SystemTun) (*tcpForwarder, error) {
	tcpForwarder := &tcpForwarder{
		tun:      tun,
		sessions: common.NewLruCache(300, true),
	}
	address := &net.TCPAddr{
		IP: tun.addr4.AsSlice(),
	}
	listener, err := net.ListenTCP("tcp4", address)
	if err != nil {
		return nil, newError("failed to create tcp forwarder at ", address.IP).Base(err)
	}
	tcpForwarder.listener4 = listener
	tcpForwarder.port4 = uint16(listener.Addr().(*net.TCPAddr).Port)
	newError("tcp forwarder started at ", listener.Addr().(*net.TCPAddr)).AtDebug().WriteToLog()
	if tun.enableIPv6 {
		address := &net.TCPAddr{
			IP: tun.addr6.AsSlice(),
		}
		listener, err := net.ListenTCP("tcp6", address)
		if err != nil {
			return nil, newError("failed to create tcp forwarder at ", address.IP).Base(err)
		}
		tcpForwarder.listener6 = listener
		tcpForwarder.port6 = uint16(listener.Addr().(*net.TCPAddr).Port)
		newError("tcp forwarder started at ", listener.Addr().(*net.TCPAddr)).AtDebug().WriteToLog()
	}
	return tcpForwarder, nil
}

func (t *tcpForwarder) dispatch(listener *net.TCPListener) error {
	conn, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	addr := conn.RemoteAddr().(*net.TCPAddr)
	key := peerKey{tcpip.AddrFromSlice(addr.IP), uint16(addr.Port)}
	var session *peerValue
	iSession, ok := t.sessions.Get(peerKey{key.destinationAddress, key.sourcePort})
	if ok {
		session = iSession.(*peerValue)
	} else {
		conn.Close()
		return newError("dropped unknown tcp session with source port ", key.sourcePort, " to destination address ", key.destinationAddress)
	}

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(session.sourceAddress.AsSlice()),
		Port:    v2rayNet.Port(key.sourcePort),
		Network: v2rayNet.Network_TCP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress(key.destinationAddress.AsSlice()),
		Port:    v2rayNet.Port(session.destinationPort),
		Network: v2rayNet.Network_TCP,
	}

	go func() {
		t.tun.handler.NewConnection(source, destination, conn)
		time.Sleep(time.Second * 5)
		t.sessions.Delete(key)
	}()

	return nil
}

func (t *tcpForwarder) dispatchLoop(listener *net.TCPListener) {
	for !t.closed {
		if err := t.dispatch(listener); err != nil {
			newError("dispatch tcp conn failed").Base(err).WriteToLog()
		}
	}
}

func (t *tcpForwarder) processIPv4(ipHdr header.IPv4, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	var session *peerValue

	if sourcePort != t.port4 {
		key := peerKey{destinationAddress, sourcePort}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			session = &peerValue{sourceAddress, destinationPort}
			t.sessions.Set(key, session)
		}
		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(tcpip.AddrFrom4(t.tun.addr4.As4()))
		tcpHdr.SetDestinationPort(t.port4)
	} else {
		iSession, ok := t.sessions.Get(peerKey{destinationAddress, destinationPort})
		if ok {
			session = iSession.(*peerValue)
		} else {
			newError("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress).AtWarning().WriteToLog()
			return
		}
		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) processIPv6(ipHdr header.IPv6, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	var session *peerValue

	if sourcePort != t.port6 {

		key := peerKey{destinationAddress, sourcePort}
		iSession, ok := t.sessions.Get(key)
		if ok {
			session = iSession.(*peerValue)
		} else {
			session = &peerValue{sourceAddress, destinationPort}
			t.sessions.Set(key, session)
		}

		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(tcpip.AddrFrom16(t.tun.addr6.As16()))
		tcpHdr.SetDestinationPort(t.port6)

	} else {

		iSession, ok := t.sessions.Get(peerKey{destinationAddress, destinationPort})
		if ok {
			session = iSession.(*peerValue)
		} else {
			newError("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress).AtWarning().WriteToLog()
			return
		}

		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) Close() error {
	t.closed = true
	_ = t.listener4.Close()
	if t.listener6 != nil {
		_ = t.listener6.Close()
	}
	return nil
}
