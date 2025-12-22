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
	"container/list"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/v2fly/v2ray-core/v5/app/proxyman/inbound"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/bytespool"
	"github.com/v2fly/v2ray-core/v5/common/log"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"libcore/comm"
	"libcore/gvisor"
	"libcore/nat"
	"libcore/tun"
)

var _ tun.Handler = (*Tun2ray)(nil)

type Tun2ray struct {
	dev                 tun.Tun
	mtu                 int32
	addr4               netip.Addr
	addr6               netip.Addr
	dns4                netip.Addr
	dns6                netip.Addr
	v2ray               *V2RayInstance
	fakedns             bool
	sniffing            bool
	overrideDestination bool

	dumpUID      bool
	trafficStats bool
	pcap         bool

	udpTable  sync.Map
	appStats  sync.Map
	lockTable sync.Map

	connectionsLock sync.Mutex
	connections     list.List

	protectCloser io.Closer
}

type TunConfig struct {
	FileDescriptor      int32
	Protect             bool
	Protector           Protector
	MTU                 int32
	V2Ray               *V2RayInstance
	Addr4               string
	Addr6               string
	Dns4                string
	Dns6                string
	EnableIPv6          bool
	Implementation      int32
	FakeDNS             bool
	Sniffing            bool
	OverrideDestination bool
	Debug               bool
	DumpUID             bool
	TrafficStats        bool
	PCap                bool
	ProtectPath         string
}

func NewTun2ray(config *TunConfig) (*Tun2ray, error) {
	t := &Tun2ray{
		mtu:                 config.MTU,
		addr4:               netip.MustParseAddr(config.Addr4),
		addr6:               netip.MustParseAddr(config.Addr6),
		dns4:                netip.MustParseAddr(config.Dns4),
		v2ray:               config.V2Ray,
		sniffing:            config.Sniffing,
		overrideDestination: config.OverrideDestination,
		fakedns:             config.FakeDNS,
		dumpUID:             config.DumpUID,
		trafficStats:        config.TrafficStats,
	}
	if len(config.Dns6) > 0 {
		t.dns6 = netip.MustParseAddr(config.Dns6)
	}

	var err error
	switch config.Implementation {
	case comm.TunImplementationGVisor:
		var pcapFile *os.File
		if config.PCap {
			timestamp := time.Now().Unix()
			path := externalAssetsPath + "/pcap/" + strconv.FormatInt(timestamp, 10) + ".pcap"
			err = os.MkdirAll(filepath.Dir(path), 0o755)
			if err != nil {
				return nil, newError("unable to create pcap dir").Base(err)
			}
			pcapFile, err = os.Create(path)
			if err != nil {
				return nil, newError("unable to create pcap file").Base(err)
			}
		}

		t.dev, err = gvisor.New(config.FileDescriptor, config.MTU, t, gvisor.DefaultNIC, config.PCap, pcapFile, config.EnableIPv6)
	case comm.TunImplementationSystem:
		t.dev, err = nat.New(config.FileDescriptor, config.MTU, t, t.addr4, t.addr6, config.EnableIPv6)
	}

	if err != nil {
		return nil, err
	}

	if !config.Protect {
		config.Protector = &noopProtector{}
	}

	if len(config.ProtectPath) > 0 {
		t.protectCloser = ServerProtect(config.ProtectPath, config.Protector)
	}

	lookupFunc := func(network, host string) ([]net.IP, error) {
		response, err := config.V2Ray.LocalResolver.LookupIP(network, host)
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
	}
	internet.UseAlternativeSystemDialer(&protectedDialer{
		protector: config.Protector,
		resolver: func(domain string) ([]net.IP, error) {
			return lookupFunc("ip", domain)
		},
	})

	return t, nil
}

func (t *Tun2ray) Close() error {
	internet.UseAlternativeSystemDialer(nil)
	comm.CloseIgnore(t.dev)
	t.connectionsLock.Lock()
	for item := t.connections.Front(); item != nil; item = item.Next() {
		common.Close(item.Value)
	}
	t.connectionsLock.Unlock()
	if t.protectCloser != nil {
		_ = t.protectCloser.Close()
	}
	return nil
}

func (t *Tun2ray) NewConnection(source v2rayNet.Destination, destination v2rayNet.Destination, conn net.Conn) {
	ib := &session.Inbound{
		Source:      source,
		Tag:         "tun",
		NetworkType: inbound.GetNetworkType(),
		SSID:        inbound.GetSSID(),
	}

	isDns := false
	if addr, err := netip.ParseAddr(destination.Address.String()); err == nil {
		isDns = addr == t.dns4 || (t.dns6.IsValid() && addr == t.dns6)
	}

	if isDns {
		if destination.Port != 53 {
			conn.Close()
			return
		}
		ib.Tag = "dns-in"
	}

	ctx := toContext(context.Background(), t.v2ray.core)
	ctx = session.ContextWithInbound(ctx, ib)
	ctx = session.ContextWithID(ctx, session.NewID())

	var uid uint16
	var self bool
	uidDumper, _ := inbound.GetUidDumper()

	if uidDumper != nil && (t.dumpUID || t.trafficStats) {
		var ipProto int32
		if destination.Network == v2rayNet.Network_TCP {
			ipProto = syscall.IPPROTO_TCP
		} else {
			ipProto = syscall.IPPROTO_UDP
		}
		u, err := uidDumper.DumpUid(ipProto, source.Address.IP().String(), int32(source.Port), destination.Address.IP().String(), int32(destination.Port))
		if err == nil {
			uid = uint16(u)
			self = int(uid) == os.Getuid()
			if !self {
				if packageName, _ := uidDumper.GetPackageName(int32(uid)); len(packageName) == 0 {
					newError("[TCP (", uid, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog(session.ExportIDToError(ctx))
				} else {
					newError("[TCP (", uid, "/", packageName, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog(session.ExportIDToError(ctx))
				}
			}
			ib.UID = uint32(uid)
		}
	}

	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    !t.overrideDestination,
		}
		if t.fakedns {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "fakedns")
		}
		if t.sniffing {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "http", "tls")
		}
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: req,
		})
	}

	var stats *appStats
	if t.trafficStats && !self && !isDns {
		if iStats, exists := t.appStats.Load(uid); exists {
			stats = iStats.(*appStats)
		} else {
			iCond, loaded := t.lockTable.LoadOrStore(uid, sync.NewCond(&sync.Mutex{}))
			cond := iCond.(*sync.Cond)
			if loaded {
				cond.L.Lock()
				cond.Wait()
				iStats, exists = t.appStats.Load(uid)
				if !exists {
					panic("unexpected sync read failed")
				}
				stats = iStats.(*appStats)
				cond.L.Unlock()
			} else {
				stats = &appStats{}
				t.appStats.Store(uid, stats)
				t.lockTable.Delete(uid)
				cond.Broadcast()
			}
		}
		atomic.AddInt32(&stats.tcpConn, 1)
		atomic.AddUint32(&stats.tcpConnTotal, 1)
		atomic.StoreInt64(&stats.deactivateAt, 0)
		defer func() {
			if atomic.AddInt32(&stats.tcpConn, -1)+atomic.LoadInt32(&stats.udpConn) == 0 {
				atomic.StoreInt64(&stats.deactivateAt, time.Now().Unix())
			}
		}()
		conn = &statsConn{conn, &stats.uplink, &stats.downlink}
	}
	t.connectionsLock.Lock()
	element := t.connections.PushBack(conn)
	t.connectionsLock.Unlock()

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     destination,
		Status: log.AccessAccepted,
	})

	proxyConn, err := t.v2ray.dial(ctx, destination)
	if err != nil {
		newError(err).AtError().WriteToLog(session.ExportIDToError(ctx))
		return
	}
	defer comm.CloseIgnore(proxyConn)
	_ = task.Run(ctx, func() error {
		_ = buf.Copy(buf.NewReader(conn), buf.NewWriter(proxyConn))
		return io.EOF
	}, func() error {
		_ = buf.Copy(buf.NewReader(proxyConn), buf.NewWriter(conn))
		return io.EOF
	})

	comm.CloseIgnore(conn)

	t.connectionsLock.Lock()
	t.connections.Remove(element)
	t.connectionsLock.Unlock()
}

func (t *Tun2ray) NewPacket(source v2rayNet.Destination, destination v2rayNet.Destination, data *buf.Buffer, writeBack func([]byte, *net.UDPAddr) (int, error)) {
	natKey := source.NetAddr()

	sendTo := func() bool {
		iConn, ok := t.udpTable.Load(natKey)
		if !ok {
			return false
		}
		conn := iConn.(net.PacketConn)
		_, err := conn.WriteTo(data.Bytes(), &net.UDPAddr{
			IP:   destination.Address.IP(),
			Port: int(destination.Port),
		})
		data.Release()
		if err != nil {
			_ = conn.Close()
		}
		return true
	}

	var cond *sync.Cond

	if sendTo() {
		return
	} else {
		iCond, loaded := t.lockTable.LoadOrStore(natKey, sync.NewCond(&sync.Mutex{}))
		cond = iCond.(*sync.Cond)
		if loaded {
			cond.L.Lock()
			cond.Wait()
			sendTo()
			cond.L.Unlock()
			return
		}
	}

	ib := &session.Inbound{
		Source:      source,
		Tag:         "tun",
		NetworkType: inbound.GetNetworkType(),
		SSID:        inbound.GetSSID(),
	}

	isDns := false
	if addr, err := netip.ParseAddr(destination.Address.String()); err == nil {
		isDns = addr == t.dns4 || (t.dns6.IsValid() && addr == t.dns6)
	}

	if isDns {
		if destination.Port != 53 {
			return
		}
		ib.Tag = "dns-in"
	}

	ctx := toContext(context.Background(), t.v2ray.core)
	ctx = session.ContextWithInbound(ctx, ib)
	ctx = session.ContextWithID(ctx, session.NewID())

	var uid uint16
	var self bool
	uidDumper, _ := inbound.GetUidDumper()

	if uidDumper != nil && (t.dumpUID || t.trafficStats) {
		var ipProto int32
		if destination.Network == v2rayNet.Network_TCP {
			ipProto = syscall.IPPROTO_TCP
		} else {
			ipProto = syscall.IPPROTO_UDP
		}
		u, err := uidDumper.DumpUid(ipProto, source.Address.IP().String(), int32(source.Port), destination.Address.IP().String(), int32(destination.Port))
		if err == nil {
			uid = uint16(u)
			self = int(uid) == os.Getuid()
			if !self {
				if packageName, _ := uidDumper.GetPackageName(int32(uid)); len(packageName) == 0 {
					newError("[UDP (", uid, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog(session.ExportIDToError(ctx))
				} else {
					newError("[UDP (", uid, "/", packageName, ")] ", source.NetAddr(), " ==> ", destination.NetAddr()).AtInfo().WriteToLog(session.ExportIDToError(ctx))
				}
			}
			ib.UID = uint32(uid)
		}
	}

	if !isDns && (t.sniffing || t.fakedns) {
		req := session.SniffingRequest{
			Enabled:      true,
			MetadataOnly: t.fakedns && !t.sniffing,
			RouteOnly:    !t.overrideDestination,
		}
		if t.fakedns {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "fakedns")
		}
		if t.sniffing {
			req.OverrideDestinationForProtocol = append(req.OverrideDestinationForProtocol, "quic")
		}
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: req,
		})
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     destination,
		Status: log.AccessAccepted,
	})

	conn, err := t.v2ray.dialUDP(ctx, destination, time.Second*300)
	if err != nil {
		newError(err).AtError().WriteToLog(session.ExportIDToError(ctx))
		return
	}

	var stats *appStats
	if t.trafficStats && !self && !isDns {
		if iStats, exists := t.appStats.Load(uid); exists {
			stats = iStats.(*appStats)
		} else {
			iCond, loaded := t.lockTable.LoadOrStore(uid, sync.NewCond(&sync.Mutex{}))
			cond := iCond.(*sync.Cond)
			if loaded {
				cond.L.Lock()
				cond.Wait()
				iStats, exists = t.appStats.Load(uid)
				if !exists {
					panic("unexpected sync read failed")
				}
				stats = iStats.(*appStats)
				cond.L.Unlock()
			} else {
				stats = &appStats{}
				t.appStats.Store(uid, stats)
				t.lockTable.Delete(uid)
				cond.Broadcast()
			}
		}
		atomic.AddInt32(&stats.udpConn, 1)
		atomic.AddUint32(&stats.udpConnTotal, 1)
		atomic.StoreInt64(&stats.deactivateAt, 0)
		defer func() {
			if atomic.AddInt32(&stats.udpConn, -1)+atomic.LoadInt32(&stats.tcpConn) == 0 {
				atomic.StoreInt64(&stats.deactivateAt, time.Now().Unix())
			}
		}()
		conn = &statsPacketConn{conn, &stats.uplink, &stats.downlink}
	}

	t.connectionsLock.Lock()
	element := t.connections.PushBack(conn)
	t.connectionsLock.Unlock()

	t.udpTable.Store(natKey, conn)

	go sendTo()

	t.lockTable.Delete(natKey)
	cond.Broadcast()

	buffer := bytespool.Alloc(t.mtu)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			break
		}
		if isDns {
			addr = nil
		}
		if addr, ok := addr.(*net.UDPAddr); ok {
			_, err = writeBack(buffer[:n], addr)
		} else {
			_, err = writeBack(buffer[:n], nil)
		}
		if err != nil {
			break
		}
	}
	bytespool.Free(buffer)
	comm.CloseIgnore(conn)
	t.udpTable.Delete(natKey)

	t.connectionsLock.Lock()
	t.connections.Remove(element)
	t.connectionsLock.Unlock()
}
