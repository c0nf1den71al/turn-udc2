// Package turnc provides connection helpers for talking to TURN servers
// over TLS ("TURNS"), including support for egressing through an HTTP
// CONNECT proxy when HTTPS_PROXY is set.
package turnc

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// TLSOptions customizes TLS verification when dialing a TURN server.
type TLSOptions struct {
	RootCAs            *x509.CertPool
	InsecureSkipVerify bool
}

// DialTLS connects to addr ("host:port" or "ip:port", optionally
// through an HTTP CONNECT proxy when HTTPS_PROXY/HTTP_PROXY is set),
// then performs a TLS handshake using serverName as the SNI/server
// name. opts may be nil for system defaults. It returns the established
// TLS connection.
func DialTLS(ctx context.Context, serverName, addr string, opts *TLSOptions) (net.Conn, error) {
	raw, err := dialRaw(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	cfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            nil,
		InsecureSkipVerify: false,
	}
	if opts != nil {
		cfg.RootCAs = opts.RootCAs
		cfg.InsecureSkipVerify = opts.InsecureSkipVerify
	}

	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", addr, err)
	}
	return tlsConn, nil
}

func dialRaw(ctx context.Context, addr string) (net.Conn, error) {
	if pu := proxyURL(); pu != nil {
		return dialViaProxy(ctx, pu, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// proxyURL returns the proxy configured via environment variables, if any.
func proxyURL() *url.URL {
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if s := os.Getenv(name); s != "" {
			if u, err := url.Parse(s); err == nil && u.Host != "" {
				return u
			}
		}
	}
	return nil
}

// dialViaProxy establishes a TCP connection to addr by issuing an HTTP
// CONNECT to the proxy. Proxy schemes other than http are not supported
// (the CONNECT exchange itself is not encrypted).
func dialViaProxy(ctx context.Context, pu *url.URL, addr string) (net.Conn, error) {
	proxyAddr := pu.Host
	if !strings.Contains(proxyAddr, ":") {
		if pu.Scheme == "https" {
			proxyAddr = net.JoinHostPort(proxyAddr, "443")
		} else {
			proxyAddr = net.JoinHostPort(proxyAddr, "80")
		}
	}

	d := net.Dialer{Timeout: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}

	// Minimal CONNECT request/response exchange.
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if pu.User != nil {
		// pass through userinfo as basic auth if password is present
		if pass, ok := pu.User.Password(); ok {
			req += "Proxy-Authorization: Basic " + basicAuth(pu.User.Username(), pass) + "\r\n"
		}
	}
	req += "\r\n"

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		conn.Close()
		return nil, fmt.Errorf("malformed CONNECT response: %q", strings.TrimSpace(statusLine))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil || code != 200 {
		conn.Close()
		return nil, fmt.Errorf("CONNECT failed: %q", strings.TrimSpace(statusLine))
	}
	// drain remaining response headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read CONNECT headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
