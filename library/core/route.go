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
	"github.com/v2fly/v2ray-core/v5/app/proxyman/inbound"
	"github.com/v2fly/v2ray-core/v5/app/proxyman/outbound"
	"github.com/v2fly/v2ray-core/v5/common/net"
)

type UidDumper inbound.UidDumper

func SetUidDumper(uidDumper UidDumper, useProcfs bool) {
	if useProcfs {
		inbound.SetUidDumper(&legacyUidDumper{uidDumper: uidDumper})
	} else {
		inbound.SetUidDumper(uidDumper)
	}
}

type legacyUidDumper struct {
	uidDumper UidDumper
}

func (d *legacyUidDumper) DumpUid(ipProto int32, srcIP string, srcPort int32, _ string, _ int32) (int32, error) {
	return querySocketUidFromProcFs(ipProto, net.ParseIP(srcIP), uint16(srcPort)), nil
}

func (d *legacyUidDumper) GetPackageName(uid int32) (string, error) {
	return d.uidDumper.GetPackageName(uid)
}

func SetNetworkType(networkType string) {
	if inbound.GetNetworkType() != networkType {
		inbound.SetNetworkType(networkType)
	}
}

func SetSSID(ssid string) {
	if inbound.GetSSID() != ssid {
		inbound.SetSSID(ssid)
	}
}

func InterfaceUpdate() {
	outbound.InterfaceUpdate()
}
