/*
Copyright (C) 2021 by clash authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package protocol

import (
	"net"
	"sort"

	"libcore/clash/transport/ssr/tools"
)

func init() {
	register("auth_chain_b", newAuthChainB, 4)
}

type authChainB struct {
	*authChainA
	dataSizeList  []int
	dataSizeList2 []int
}

func newAuthChainB(b *Base) Protocol {
	a := &authChainB{
		authChainA: &authChainA{
			Base:     b,
			authData: &authData{},
			userData: &userData{},
			salt:     "auth_chain_b",
		},
	}
	a.initUserData()
	return a
}

func (a *authChainB) StreamConn(c net.Conn, iv []byte) net.Conn {
	p := &authChainB{
		authChainA: &authChainA{
			Base:     a.Base,
			authData: a.next(),
			userData: a.userData,
			salt:     a.salt,
			packID:   1,
			recvID:   1,
		},
	}
	p.iv = iv
	p.randDataLength = p.getRandLength
	p.initDataSize()
	return &Conn{Conn: c, Protocol: p}
}

func (a *authChainB) initDataSize() {
	a.dataSizeList = a.dataSizeList[:0]
	a.dataSizeList2 = a.dataSizeList2[:0]

	a.randomServer.InitFromBin(a.Key)
	length := a.randomServer.Next()%8 + 4
	for ; length > 0; length-- {
		a.dataSizeList = append(a.dataSizeList, int(a.randomServer.Next()%2340%2040%1440))
	}
	sort.Ints(a.dataSizeList)

	length = a.randomServer.Next()%16 + 8
	for ; length > 0; length-- {
		a.dataSizeList2 = append(a.dataSizeList2, int(a.randomServer.Next()%2340%2040%1440))
	}
	sort.Ints(a.dataSizeList2)
}

func (a *authChainB) getRandLength(length int, lashHash []byte, random *tools.XorShift128Plus) int {
	if length >= 1440 {
		return 0
	}
	random.InitFromBinAndLength(lashHash, length)
	pos := sort.Search(len(a.dataSizeList), func(i int) bool { return a.dataSizeList[i] >= length+a.Overhead })
	finalPos := pos + int(random.Next()%uint64(len(a.dataSizeList)))
	if finalPos < len(a.dataSizeList) {
		return a.dataSizeList[finalPos] - length - a.Overhead
	}

	pos = sort.Search(len(a.dataSizeList2), func(i int) bool { return a.dataSizeList2[i] >= length+a.Overhead })
	finalPos = pos + int(random.Next()%uint64(len(a.dataSizeList2)))
	if finalPos < len(a.dataSizeList2) {
		return a.dataSizeList2[finalPos] - length - a.Overhead
	}
	if finalPos < pos+len(a.dataSizeList2)-1 {
		return 0
	}
	if length > 1300 {
		return int(random.Next() % 31)
	}
	if length > 900 {
		return int(random.Next() % 127)
	}
	if length > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}
