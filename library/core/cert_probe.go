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

	v2tls "github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

type CertProbeResult struct {
	Cert        string
	VerifyError string
	Error       string
}

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
	defer tlsConn.Close()
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}
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

func ProbeCert(host string, port int32, sni, alpn string, protocol string, useSOCKS5 bool, socksPort int32) *CertProbeResult {
	if len(host) == 0 {
		return &CertProbeResult{
			Error: "empty host",
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var nextProto []string
	if len(alpn) > 0 {
		nextProto = strings.Split(alpn, ",")
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	var certs []*x509.Certificate
	var err error
	switch protocol {
	case "tls":
		certs, err = ProbeCertTLS(ctx, address, sni, nextProto, useSOCKS5, int(socksPort))
	case "quic":
		certs, err = ProbeCertQUIC(ctx, address, sni, nextProto, useSOCKS5, int(socksPort))
	default:
		panic("unknown protocol: " + protocol)
	}
	if err != nil {
		return &CertProbeResult{
			Error: err.Error(),
		}
	}
	var builder strings.Builder
	for _, cert := range certs {
		err = pem.Encode(&builder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return &CertProbeResult{
				Error: err.Error(),
			}
		}
	}
	result := &CertProbeResult{
		Cert: builder.String(),
	}
	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
	}
	if len(sni) > 0 {
		opts.DNSName = sni
	} else {
		opts.DNSName = host
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, verifyErr := certs[0].Verify(opts); verifyErr != nil {
		result.VerifyError = verifyErr.Error()
	}
	return result
}

func CalculatePEMCertSHA256Hash(input string) (string, error) {
	return v2tls.CalculatePEMCertSHA256Hash([]byte(input))
}

func CalculatePEMCertPublicKeySHA256Hash(input string) (string, error) {
	return v2tls.CalculatePEMCertPublicKeySHA256Hash([]byte(input))
}

func CalculatePEMCertChainSHA256Hash(input string) (string, error) {
	return v2tls.CalculatePEMCertChainSHA256Hash([]byte(input)), nil
}
