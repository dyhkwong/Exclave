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
	"os"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"libcore/tun"
)

//go:generate go run ../errorgen

var _ tun.Tun = (*SystemTun)(nil)

var (
	vlanClient4 = tcpip.AddrFromSlice([]uint8{172, 19, 0, 1})
	vlanClient6 = tcpip.AddrFromSlice([]uint8{0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1})
)

type SystemTun struct {
	dev          int
	mtu          int
	handler      tun.Handler
	enableIPv6   bool
	tcpForwarder *tcpForwarder
}

func New(dev int32, mtu int32, handler tun.Handler, enableIPv6 bool) (*SystemTun, error) {
	t := &SystemTun{
		dev:        int(dev),
		mtu:        int(mtu),
		handler:    handler,
		enableIPv6: enableIPv6,
	}
	tcpServer, err := newTcpForwarder(t)
	if err != nil {
		return nil, err
	}
	t.tcpForwarder = tcpServer
	go tcpServer.dispatchLoop(tcpServer.listener4)
	if t.enableIPv6 {
		go tcpServer.dispatchLoop(tcpServer.listener6)
	}

	go t.dispatchLoop()
	return t, nil
}

func (t *SystemTun) dispatchLoop() {
	cache := buf.NewWithSize(int32(t.mtu))
	defer func() {
		cache.Release()
	}()
	data := cache.Extend(cache.Cap())

	device := os.NewFile(uintptr(t.dev), "tun")

	for {
		n, err := device.Read(data)
		if err != nil {
			break
		}
		cache.Clear()
		cache.Resize(0, int32(n))
		packet := data[:n]
		if t.deliverPacket(cache, packet) {
			cache = buf.NewWithSize(int32(t.mtu))
			data = cache.Extend(cache.Cap())
		}
	}
}

func (t *SystemTun) writeRawPacket(pkt *stack.PacketBuffer) tcpip.Error {
	views := pkt.AsSlices()
	iovecs := make([]unix.Iovec, len(views))
	for i, v := range views {
		iovecs[i] = rawfile.IovecFromBytes(v)
	}
	if errno := rawfile.NonBlockingWriteIovec(t.dev, iovecs); errno != 0 {
		return tcpip.TranslateErrno(errno)
	}
	return nil
}

func (t *SystemTun) writeBuffer(bytes []byte) tcpip.Error {
	if errno := rawfile.NonBlockingWrite(t.dev, bytes); errno != 0 {
		return tcpip.TranslateErrno(errno)
	}
	return nil
}

func (t *SystemTun) deliverPacket(cache *buf.Buffer, packet []byte) bool {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		switch ipHdr.TransportProtocol() {
		case header.TCPProtocolNumber:
			t.tcpForwarder.processIPv4(ipHdr, ipHdr.Payload())
		case header.UDPProtocolNumber:
			t.processIPv4UDP(cache, ipHdr, ipHdr.Payload())
			return true
		case header.ICMPv4ProtocolNumber:
			t.processICMPv4(ipHdr, ipHdr.Payload())
		}
	case header.IPv6Version:
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		proto, _, _, _, ok := parse.IPv6(pkt)
		pkt.DecRef()
		if !ok {
			return false
		}
		ipHdr := header.IPv6(packet)
		switch proto {
		case header.TCPProtocolNumber:
			t.tcpForwarder.processIPv6(ipHdr, ipHdr.Payload())
		case header.UDPProtocolNumber:
			t.processIPv6UDP(cache, ipHdr, ipHdr.Payload())
			return true
		case header.ICMPv6ProtocolNumber:
			t.processICMPv6(ipHdr, ipHdr.Payload())
		}
	}
	return false
}

func (t *SystemTun) Close() error {
	return t.tcpForwarder.Close()
}
