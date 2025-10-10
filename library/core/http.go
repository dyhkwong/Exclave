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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/wzshiming/socks5"
)

type HTTPClient interface {
	RestrictedTLS()
	ModernTLS()
	PinnedTLS12()
	PinnedSHA256(sumHex string)
	TrySocks5(port int32)
	UseSocks5(port int32)
	KeepAlive()
	NewRequest() HTTPRequest
	Close()
}

type HTTPRequest interface {
	SetURL(link string) error
	SetMethod(method string)
	SetHeader(key string, value string)
	SetContent(content []byte)
	SetContentString(content string)
	SetUserAgent(userAgent string)
	Execute() (HTTPResponse, error)
}

type HTTPResponse interface {
	GetContent() []byte
	GetContentString() string
	GetHeader(key string) string
	WriteTo(path string) error
}

var (
	_ HTTPClient   = (*httpClient)(nil)
	_ HTTPRequest  = (*httpRequest)(nil)
	_ HTTPResponse = (*httpResponse)(nil)
)

type httpClient struct {
	tls       tls.Config
	client    http.Client
	transport http.Transport
}

func NewHttpClient() HTTPClient {
	client := new(httpClient)
	client.client.Transport = &client.transport
	client.transport.TLSClientConfig = &client.tls
	client.transport.DisableKeepAlives = true
	client.transport.ForceAttemptHTTP2 = true
	return client
}

func (c *httpClient) ModernTLS() {
	c.tls.MinVersion = tls.VersionTLS12
	c.tls.CipherSuites = Map(tls.CipherSuites(), func(it *tls.CipherSuite) uint16 { return it.ID })
}

func (c *httpClient) RestrictedTLS() {
	c.tls.MinVersion = tls.VersionTLS13
	c.tls.CipherSuites = Map(Filter(tls.CipherSuites(), func(it *tls.CipherSuite) bool {
		return Contains(it.SupportedVersions, uint16(tls.VersionTLS13))
	}), func(it *tls.CipherSuite) uint16 {
		return it.ID
	})
}

func (c *httpClient) PinnedTLS12() {
	c.tls.MinVersion = tls.VersionTLS12
	c.tls.MaxVersion = tls.VersionTLS12
}

func (c *httpClient) PinnedSHA256(sumHex string) {
	// Only used in OOC v1.
	//
	// "Certificate SHA-256 Fingerprint: Optional.
	// Pin the server certificate by verifying the certificate fingerprint.
	// Required only when using a self-signed certificate."
	//
	// "The certSha256 field is required when using a self-signed certificate.
	// With a publicly-trusted certificate, this field SHOULD be omitted."
	//
	// So we have to skip the Go TLS certificate verification logic
	// and handcraft a custom certificate verification logic.
	c.tls.InsecureSkipVerify = true
	c.tls.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		opts := x509.VerifyOptions{
			DNSName:       c.tls.ServerName,
			Roots:         c.tls.RootCAs,
			Intermediates: x509.NewCertPool(),
		}
		if c.tls.Time != nil {
			opts.CurrentTime = c.tls.Time()
		}
		for _, rawCert := range rawCerts[1:] {
			cert, _ := x509.ParseCertificate(rawCert)
			opts.Intermediates.AddCert(cert)
		}
		cert, _ := x509.ParseCertificate(rawCerts[0])
		_, err := cert.Verify(opts)
		if err == nil {
			return nil
		}
		certSum := sha256.Sum256(rawCerts[0])
		if sumHex == hex.EncodeToString(certSum[:]) {
			return nil
		}
		return err
	}
}

// not used
func (c *httpClient) TrySocks5(port int32) {
	dialer := new(net.Dialer)
	socks5Dialer, _ := socks5.NewDialer("socks5h://127.0.0.1:" + strconv.Itoa(int(port)))
	c.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		for {
			socksConn, err := socks5Dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				break
			}
			return socksConn, err
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

func (c *httpClient) UseSocks5(port int32) {
	c.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer, _ := socks5.NewDialer("socks5h://127.0.0.1:" + strconv.Itoa(int(port)))
		return dialer.DialContext(ctx, network, addr)
	}
}

func (c *httpClient) KeepAlive() {
	c.transport.DisableKeepAlives = false
}

func (c *httpClient) NewRequest() HTTPRequest {
	req := &httpRequest{httpClient: c}
	req.request = http.Request{
		Method: "GET",
		Header: http.Header{},
	}
	return req
}

func (c *httpClient) Close() {
	c.transport.CloseIdleConnections()
}

type httpRequest struct {
	*httpClient
	request http.Request
}

func (r *httpRequest) SetURL(link string) (err error) {
	r.request.URL, err = url.Parse(link)
	if err != nil {
		return err
	}
	if r.request.URL != nil && r.request.URL.User != nil {
		user := r.request.URL.User.Username()
		password, _ := r.request.URL.User.Password()
		r.request.SetBasicAuth(user, password)
	}
	return
}

func (r *httpRequest) SetMethod(method string) {
	r.request.Method = method
}

func (r *httpRequest) SetHeader(key string, value string) {
	r.request.Header.Set(key, value)
}

func (r *httpRequest) SetUserAgent(userAgent string) {
	r.request.Header.Set("User-Agent", userAgent)
}

func (r *httpRequest) SetContent(content []byte) {
	buffer := bytes.Buffer{}
	buffer.Write(content)
	r.request.Body = io.NopCloser(bytes.NewReader(buffer.Bytes()))
	r.request.ContentLength = int64(len(content))
}

func (r *httpRequest) SetContentString(content string) {
	r.SetContent([]byte(content))
}

func (r *httpRequest) Execute() (HTTPResponse, error) {
	response, err := r.client.Do(&r.request)
	if err != nil {
		return nil, err
	}
	httpResp := &httpResponse{Response: response}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New(httpResp.errorString())
	}
	return httpResp, nil
}

type httpResponse struct {
	*http.Response

	getContentOnce sync.Once
	content        []byte
	contentError   error
}

func (h *httpResponse) errorString() string {
	content := h.GetContentString()
	if h.contentError != nil {
		return fmt.Sprint("HTTP ", h.Status)
	}
	return fmt.Sprint("HTTP ", h.Status, ": ", content)
}

func (h *httpResponse) GetContent() []byte {
	h.getContentOnce.Do(func() {
		defer h.Body.Close()
		h.content, h.contentError = io.ReadAll(h.Body)
	})
	if h.contentError != nil {
		return nil
	}
	return h.content
}

func (h *httpResponse) GetContentString() string {
	content := h.GetContent()
	if h.contentError != nil {
		return ""
	}
	return string(content)
}

func (r *httpResponse) GetHeader(key string) string {
	return r.Response.Header.Get(key)
}

func (h *httpResponse) WriteTo(path string) error {
	defer h.Body.Close()
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := buf.StackNew()
	defer buffer.Release()
	_, err = io.CopyBuffer(file, h.Body, buffer.Extend(buf.Size))
	return err
}
