/*
MIT License

Copyright (c) 2024 HystericalDragon HystericalDragons@proton.me

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// modified from https://github.com/xchacha20-poly1305/TLS-scribe

package libcore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/wzshiming/socks5"
)

func ProbeCertTLS(ctx context.Context, address, sni string, alpn []string, useSOCKS5 bool, socksPort int) ([]*x509.Certificate, error) {
	var conn net.Conn
	var err error
	if useSOCKS5 {
		dialer, _ := socks5.NewDialer("socks5h://127.0.0.1:" + strconv.Itoa(socksPort))
		conn, err = dialer.DialContext(ctx, "tcp", address)
	} else {
		dialer := new(net.Dialer)
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         alpn,
		ServerName:         sni,
	})
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}
	defer tlsConn.Close()
	return tlsConn.ConnectionState().PeerCertificates, nil
}

type udpAddr struct {
	address string
}

func (a *udpAddr) Network() string {
	return "udp"
}

func (a *udpAddr) String() string {
	return a.address
}

func ProbeCertQUIC(ctx context.Context, address, sni string, alpn []string, useSOCKS5 bool, socksPort int) ([]*x509.Certificate, error) {
	var packetConn net.PacketConn
	var addr net.Addr
	var err error
	if useSOCKS5 {
		dialer, _ := socks5.NewDialer("socks5h://127.0.0.1:" + strconv.Itoa(socksPort))
		conn, err := dialer.DialContext(ctx, "udp", address)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		packetConn = conn.(*socks5.UDPConn)
		addr = &udpAddr{address: address}
	} else {
		packetConn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		defer packetConn.Close()
		addr, err = net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
	}
	quicConn, err := quic.Dial(ctx, packetConn, addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         alpn,
		ServerName:         sni,
	}, &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}})
	if err != nil {
		return nil, err
	}
	defer quicConn.CloseWithError(0x00, "")
	return quicConn.ConnectionState().TLS.PeerCertificates, nil
}

func ProbeCert(address, sni, alpn, protocol string, useSOCKS5 bool, socksPort int32) (cert string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var certs []*x509.Certificate
	var nextProto []string
	if len(alpn) > 0 {
		nextProto = strings.Split(alpn, ",")
	}
	switch protocol {
	case "tls":
		certs, err = ProbeCertTLS(ctx, address, sni, nextProto, useSOCKS5, int(socksPort))
	case "quic":
		certs, err = ProbeCertQUIC(ctx, address, sni, nextProto, useSOCKS5, int(socksPort))
	default:
		err = newError("unknown protocol: ", protocol)
	}
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	for _, cert := range certs {
		err = pem.Encode(&builder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", err
		}
	}
	return builder.String(), nil
}
