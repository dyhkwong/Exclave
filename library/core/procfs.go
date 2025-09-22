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
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/v2fly/v2ray-core/v5/common/net"
)

var (
	once sync.Once

	netIndexOfLocal = -1
	netIndexOfUid   = -1
	nativeEndian    binary.ByteOrder
)

func querySocketUidFromProcFs(ipProto int32, srcIP net.IP, srcPort uint16) int32 {
	once.Do(Init)
	if netIndexOfLocal < 0 || netIndexOfUid < 0 {
		return -1
	}

	path := "/proc/net/"

	switch ipProto {
	case syscall.IPPROTO_TCP:
		path += "tcp"
	case syscall.IPPROTO_UDP:
		path += "udp"
	}

	if srcIP.To4() == nil {
		path += "6"
	} else {
		srcIP = srcIP.To4()
	}

	var bytes [2]byte
	binary.BigEndian.PutUint16(bytes[:], srcPort)
	local := fmt.Sprintf("%s:%s", hex.EncodeToString(nativeEndianIP(srcIP)), hex.EncodeToString(bytes[:]))

	file, err := os.Open(path)
	if err != nil {
		return -1
	}

	defer file.Close()

	reader := bufio.NewReader(file)

	for {
		row, _, err := reader.ReadLine()
		if err != nil {
			return -1
		}

		fields := strings.Fields(string(row))

		if len(fields) <= netIndexOfLocal || len(fields) <= netIndexOfUid {
			continue
		}

		if strings.EqualFold(local, fields[netIndexOfLocal]) {
			uid, err := strconv.Atoi(fields[netIndexOfUid])
			if err != nil {
				return -1
			}

			return int32(uid)
		}
	}
}

func nativeEndianIP(ip net.IP) []byte {
	result := make([]byte, len(ip))

	for i := 0; i < len(ip); i += 4 {
		value := binary.BigEndian.Uint32(ip[i:])

		nativeEndian.PutUint32(result[i:], value)
	}

	return result
}

func Init() {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		fmt.Println(err)
		return
	}

	defer file.Close()

	reader := bufio.NewReader(file)

	header, _, err := reader.ReadLine()
	if err != nil {
		return
	}

	columns := strings.Fields(string(header))

	var txQueue, rxQueue, tr, tmWhen bool

	for idx, col := range columns {
		offset := 0

		if txQueue && rxQueue {
			offset--
		}

		if tr && tmWhen {
			offset--
		}

		switch col {
		case "tx_queue":
			txQueue = true
		case "rx_queue":
			rxQueue = true
		case "tr":
			tr = true
		case "tm->when":
			tmWhen = true
		case "local_address":
			netIndexOfLocal = idx + offset
		case "uid":
			netIndexOfUid = idx + offset
		}
	}

	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
}
