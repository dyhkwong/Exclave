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

package obfs

import (
	"errors"
	"fmt"
	"net"
)

var (
	errTLS12TicketAuthIncorrectMagicNumber = errors.New("tls1.2_ticket_auth incorrect magic number")
	errTLS12TicketAuthTooShortData         = errors.New("tls1.2_ticket_auth too short data")
	errTLS12TicketAuthHMACError            = errors.New("tls1.2_ticket_auth hmac verifying failed")
)

type authData struct {
	clientID [32]byte
}

type Obfs interface {
	StreamConn(net.Conn) net.Conn
}

type obfsCreator func(b *Base) Obfs

var obfsList = make(map[string]struct {
	overhead int
	new      obfsCreator
})

func register(name string, c obfsCreator, o int) {
	obfsList[name] = struct {
		overhead int
		new      obfsCreator
	}{overhead: o, new: c}
}

func PickObfs(name string, b *Base) (Obfs, int, error) {
	if choice, ok := obfsList[name]; ok {
		return choice.new(b), choice.overhead, nil
	}
	return nil, 0, fmt.Errorf("Obfs %s not supported", name)
}
