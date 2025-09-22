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
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.InjectableLinkEndpoint = (*rwEndpoint)(nil)

// rwEndpoint implements the interface of stack.LinkEndpoint from io.ReadWriter.
type rwEndpoint struct {
	fd int

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32
	wg  sync.WaitGroup

	inbound    *readVDispatcher
	dispatcher stack.NetworkDispatcher

	mu sync.RWMutex `state:"nosave"`
}

func newRwEndpoint(dev int32, mtu int32) (*rwEndpoint, error) {
	e := &rwEndpoint{
		fd:  int(dev),
		mtu: uint32(mtu),
	}
	i, err := newReadVDispatcher(e.fd, e)
	if err != nil {
		return nil, err
	}
	e.inbound = i
	return e, nil
}

func (e *rwEndpoint) InjectInbound(networkProtocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	go e.dispatcher.DeliverNetworkPacket(networkProtocol, pkt)
}

func (e *rwEndpoint) InjectOutbound(dest tcpip.Address, packet *buffer.View) tcpip.Error {
	if errno := rawfile.NonBlockingWrite(e.fd, packet.AsSlice()); errno != 0 {
		return tcpip.TranslateErrno(errno)
	}
	return nil
}

// Attach launches the goroutine that reads packets from io.ReadWriter and
// dispatches them via the provided dispatcher.
func (e *rwEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil && e.dispatcher != nil {
		e.inbound.stop()
		e.Wait()
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		e.dispatcher = dispatcher
		e.wg.Add(1)
		go func() {
			e.dispatchLoop(e.inbound)
			e.wg.Done()
		}()
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *rwEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *rwEndpoint) dispatchLoop(inboundDispatcher *readVDispatcher) tcpip.Error {
	for {
		cont, err := inboundDispatcher.dispatch()
		if err != nil || !cont {
			return err
		}
	}
}

// WritePackets writes packets back into io.ReadWriter.
func (e *rwEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// Preallocate to avoid repeated reallocation as we append to batch.
	// batchSz is 47 because when SWGSO is in use then a single 65KB TCP
	// segment can get split into 46 segments of 1420 bytes and a single 216
	// byte segment.
	const batchSz = 47
	batch := make([]unix.Iovec, 0, batchSz)
	for _, pkt := range pkts.AsSlice() {
		batch = rawfile.AppendIovecFromBytes(batch, pkt.ToView().AsSlice(), rawfile.MaxIovs)
	}
	if errno := rawfile.NonBlockingWriteIovec(e.fd, batch); errno != 0 {
		return 0, tcpip.TranslateErrno(errno)
	}
	return pkts.Len(), nil
}

// MTU implements stack.LinkEndpoint.MTU.
func (e *rwEndpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *rwEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*rwEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (*rwEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*rwEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *rwEndpoint) AddHeader(*stack.PacketBuffer) {
}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (*rwEndpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
func (e *rwEndpoint) SetLinkAddress(_ tcpip.LinkAddress) {}

// SetMTU implements stack.LinkEndpoint.SetMTU.
func (e *rwEndpoint) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
}

// SetOnCloseAction implements stack.LinkEndpoint.
func (*rwEndpoint) SetOnCloseAction(func()) {}

// Wait implements stack.LinkEndpoint.Wait.
func (e *rwEndpoint) Wait() {
	e.wg.Wait()
}

// Close implements stack.LinkEndpoint.Close.
func (*rwEndpoint) Close() {}
