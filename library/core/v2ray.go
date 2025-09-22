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
	"os"
	"strconv"
	"strings"
	_ "unsafe"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/features"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/dns/localdns"
	"github.com/v2fly/v2ray-core/v5/features/extension"
	"github.com/v2fly/v2ray-core/v5/features/stats"
	"github.com/v2fly/v2ray-core/v5/infra/conf/serial"
	_ "github.com/v2fly/v2ray-core/v5/main/distro/all"
)

func GetV2RayVersion() string {
	return core.Version()
}

type V2RayInstanceConfig struct {
	LocalResolver LocalResolver
}

type V2RayInstance struct {
	started       bool
	core          *core.Instance
	statsManager  stats.Manager
	observatory   features.TaggedFeatures
	LocalResolver LocalResolver
}

func NewV2rayInstance(config *V2RayInstanceConfig) *V2RayInstance {
	return &V2RayInstance{
		LocalResolver: config.LocalResolver,
	}
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

	if instance.LocalResolver != nil {
		localdns.SetLookupFunc(func(network, host string) ([]net.IP, error) {
			response, err := instance.LocalResolver.LookupIP(network, host)
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
			addrs := Filter(strings.Split(response, ","), func(it string) bool {
				return len(strings.TrimSpace(it)) >= 0
			})
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
		if instance.LocalResolver.SupportExchange() {
			localdns.SetRawQueryFunc(func(b []byte) ([]byte, error) {
				return instance.LocalResolver.Exchange(b)
			})
		}
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
		if instance.LocalResolver != nil {
			localdns.SetLookupFunc(nil)
			localdns.SetRawQueryFunc(nil)
		}
		instance.core = nil
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

func (instance *V2RayInstance) dialUDP(ctx context.Context) (net.PacketConn, error) {
	if !instance.started {
		return nil, os.ErrInvalid
	}
	return core.DialUDP(ctx, instance.core)
}
