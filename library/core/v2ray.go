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

package libcore

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol/udp"
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/v2fly/v2ray-core/v5/features"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/dns/localdns"
	"github.com/v2fly/v2ray-core/v5/features/extension"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/features/stats"
	"github.com/v2fly/v2ray-core/v5/infra/conf/serial"
	_ "github.com/v2fly/v2ray-core/v5/main/distro/all"
	"github.com/v2fly/v2ray-core/v5/transport"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

var (
	systemDialerMutex       sync.Mutex
	systemDialer            internet.SystemDialer
	systemDialerWithProtect internet.SystemDialer
)

func GetGoVersion() string {
	return strings.TrimPrefix(runtime.Version(), "go")
}

func GetDepInfo() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return strings.ReplaceAll(info.String(), "\t", " ")
	}
	return ""
}

func GetV2RayVersion() string {
	return core.Version()
}

type V2RayInstance struct {
	started       bool
	core          *core.Instance
	dispatcher    routing.Dispatcher
	statsManager  stats.Manager
	observatory   features.TaggedFeatures
	localResolver LocalResolver
}

func (instance *V2RayInstance) WithLocalResolver(localResolver LocalResolver) {
	if localResolver == nil {
		instance.localResolver = nil
		localdns.SetLookupFunc(nil)
		localdns.SetRawQueryFunc(nil)
		return
	}
	instance.localResolver = localResolver
	localdns.SetLookupFunc(func(network, host string) ([]net.IP, error) {
		response, err := localResolver.LookupIP(network, host)
		if err != nil {
			errStr := err.Error()
			if strings.HasPrefix(errStr, "rcode") {
				r, _ := strconv.Atoi(strings.Split(errStr, " ")[1])
				return nil, dns.RCodeError(r)
			}
			return nil, err
		}
		if response == "" {
			return nil, dns.ErrEmptyResponse
		}
		addrs := strings.Split(response, ",")
		ips := make([]net.IP, len(addrs))
		for i, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip.To4() != nil {
				ip = ip.To4()
			}
			ips[i] = ip
		}
		if len(ips) == 0 {
			return nil, dns.ErrEmptyResponse
		}
		return ips, nil
	})
	if localResolver.SupportExchange() {
		localdns.SetRawQueryFunc(func(b []byte) ([]byte, error) {
			return localResolver.Exchange(b)
		})
	}
}

func (instance *V2RayInstance) WithProtect(path string) {
	systemDialerMutex.Lock()
	defer systemDialerMutex.Unlock()
	if len(path) == 0 {
		if systemDialer == nil {
			systemDialer = &internet.DefaultSystemDialer{}
		}
		internet.UseAlternativeSystemDialer(systemDialer)
		return
	}
	if systemDialerWithProtect == nil {
		systemDialerWithProtect = &internet.DefaultSystemDialer{}
		controller := func(_, _ string, fd uintptr) error {
			return protect(path, fd)
		}
		// TODO: export internet.DefaultSystemDialer.controllers to avoid reflect
		ptr := (*[]func(string, string, uintptr) error)(unsafe.Pointer(reflect.ValueOf(systemDialerWithProtect).Elem().FieldByName("controllers").UnsafeAddr()))
		*ptr = []func(string, string, uintptr) error{controller}
	}
	internet.UseAlternativeSystemDialer(systemDialerWithProtect)
}

func (instance *V2RayInstance) LoadConfig(content string) error {
	config, err := serial.LoadJSONConfig(strings.NewReader(content))
	if err != nil {
		return err
	}
	instance.core, err = core.New(config)
	if err != nil {
		return err
	}
	instance.dispatcher = instance.core.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	instance.statsManager = instance.core.GetFeature(stats.ManagerType()).(stats.Manager)
	o := instance.core.GetFeature(extension.ObservatoryType())
	if o != nil {
		instance.observatory = o.(features.TaggedFeatures)
	}
	return nil
}

func (instance *V2RayInstance) Start() error {
	if instance.started {
		return newError("already started")
	}
	if instance.core == nil {
		return newError("not initialized")
	}

	if err := instance.core.Start(); err != nil {
		return err
	}
	instance.started = true
	return nil
}

func (instance *V2RayInstance) QueryStats(tag string, direct string) int64 {
	if instance.statsManager == nil {
		return 0
	}
	counter := instance.statsManager.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>%s", tag, direct))
	if counter == nil {
		return 0
	}
	return counter.Set(0)
}

func (instance *V2RayInstance) Close() error {
	if instance.started {
		instance.core.Close()
		instance.core = nil
		instance.dispatcher = nil
		instance.statsManager = nil
		instance.observatory = nil
		instance.started = false
	}
	return nil
}

//go:linkname toContext github.com/v2fly/v2ray-core/v5.toContext
func toContext(ctx context.Context, v *core.Instance) context.Context

func (instance *V2RayInstance) dial(ctx context.Context, destination net.Destination) (net.Conn, error) {
	if !instance.started {
		return nil, os.ErrInvalid
	}
	return core.Dial(ctx, instance.core, destination)
}

/*func (instance *V2RayInstance) dialUDP(ctx context.Context) (net.PacketConn, error) {
	if !instance.started {
		return nil, os.ErrInvalid
	}
	return core.DialUDP(ctx, instance.core)
}*/

func (instance *V2RayInstance) dialUDP(ctx context.Context, destination net.Destination, timeout time.Duration) (net.PacketConn, error) {
	if !instance.started {
		return nil, os.ErrInvalid
	}
	ctx, cancel := context.WithCancel(ctx)
	link, err := instance.dispatcher.Dispatch(ctx, destination)
	if err != nil {
		cancel()
		return nil, err
	}
	c := &dispatcherConn{
		dest:   destination,
		link:   link,
		ctx:    ctx,
		cancel: cancel,
		cache:  make(chan *udp.Packet, 16),
	}
	c.timer = signal.CancelAfterInactivity(ctx, func() {
		c.Close()
	}, timeout)
	go c.handleInput()
	return c, nil
}

type dispatcherConn struct {
	dest      net.Destination
	link      *transport.Link
	timer     *signal.ActivityTimer
	cache     chan *udp.Packet
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func (c *dispatcherConn) handleInput() {
	defer c.Close()
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		mb, err := c.link.Reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			return
		}
		c.timer.Update()
		for _, buffer := range mb {
			if buffer.IsEmpty() {
				continue
			}
			packet := &udp.Packet{
				Payload: buffer,
				Source:  c.dest,
			}
			if buffer.Endpoint != nil {
				packet.Source = *buffer.Endpoint
			}
			select {
			case c.cache <- packet:
				continue
			case <-c.ctx.Done():
			default:
			}
			buffer.Release()
		}
	}
}

func (c *dispatcherConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, io.EOF
	case packet, ok := <-c.cache:
		if !ok {
			return 0, nil, io.EOF
		}
		n := copy(p, packet.Payload.Bytes())
		packet.Payload.Release()
		return n, &net.UDPAddr{
			IP:   packet.Source.Address.IP(),
			Port: int(packet.Source.Port),
		}, nil
	}
}

func (c *dispatcherConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewWithSize(int32(len(p)))
	buffer.Write(p)
	endpoint := net.DestinationFromAddr(addr)
	buffer.Endpoint = &endpoint
	err = c.link.Writer.WriteMultiBuffer(buf.MultiBuffer{buffer})
	if err != nil {
		buffer.Release()
		c.Close()
		return 0, err
	} else {
		c.timer.Update()
		n = len(p)
	}
	return
}

func (c *dispatcherConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   []byte{0, 0, 0, 0},
		Port: 0,
	}
}

func (c *dispatcherConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		_ = common.Interrupt(c.link.Reader)
		_ = common.Interrupt(c.link.Writer)
		close(c.cache)
	})
	return nil
}

func (c *dispatcherConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetWriteDeadline(t time.Time) error {
	return nil
}
