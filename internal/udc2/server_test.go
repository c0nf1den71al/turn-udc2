package udc2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pion/transport/v2/stdnet"
	"github.com/pion/turn/v2"

	"github.com/jamiepegg/turn-c2/internal/proto"
	"github.com/jamiepegg/turn-c2/internal/turnc"
)

const (
	testUser     = "user"
	testPass     = "pass"
	testRealm    = "turn-c2.test"
	testTurnHost = "turn-c2.test"
)

// TestEndToEnd spins up an in-process TURN server (over TLS), a fake
// team server, and the UDC2 server, then drives the Beacon side of the
// protocol the same way the BOF does: allocate a relay, permit the
// operator relay IP, send a chunked Beacon frame, and verify the echoed
// response round trips.
func TestEndToEnd(t *testing.T) {
	// --- TURN server over TLS ---
	cert := selfSignedCert(t, testTurnHost)
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer tlsLn.Close()

	netStack, err := stdnet.NewNet()
	if err != nil {
		t.Fatalf("stdnet: %v", err)
	}
	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm: testRealm,
		AuthHandler: func(username, realm string, src net.Addr) ([]byte, bool) {
			if username == testUser {
				return turn.GenerateAuthKey(username, realm, testPass), true
			}
			return nil, false
		},
		InboundMTU: 65536,
		ListenerConfigs: []turn.ListenerConfig{{
			Listener: tlsLn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
				Net:          netStack,
			},
		}},
	})
	if err != nil {
		t.Fatalf("turn server: %v", err)
	}
	defer turnServer.Close()
	turnPort := tlsLn.Addr().(*net.TCPAddr).Port

	// --- fake team server (echo) ---
	tsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ts listen: %v", err)
	}
	defer tsLn.Close()
	go serveEchoTS(t, tsLn)
	tsPort := tsLn.Addr().(*net.TCPAddr).Port

	// --- UDC2 server ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan *net.UDPAddr, 1)
	cfg := Config{
		// Hostname is used for TLS SNI; the ephemeral port comes from the
		// listener and the connection is pinned to 127.0.0.1.
		TurnServer:   net.JoinHostPort(testTurnHost, strconv.Itoa(turnPort)),
		TurnServerIP: "127.0.0.1",
		Username:     testUser,
		Password:     testPass,
		TSAddr:       "127.0.0.1",
		TSPort:       tsPort,
		ChunkSize:    1024,
		MaxFrameSize: 1 << 20,
		RootCAs:      certPool(t, cert),
		Verbose:      true,
		OnReady:      func(relayAddr *net.UDPAddr, serverAddr net.Addr) { ready <- relayAddr },
	}

	serverDone := make(chan error, 1)
	go func() { serverDone <- Run(ctx, cfg, log.New(os.Stderr, "[udc2] ", log.LstdFlags)) }()

	var relayAddr *net.UDPAddr
	select {
	case relayAddr = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("udc2 server not ready in time")
	case err := <-serverDone:
		t.Fatalf("udc2 server exited early: %v", err)
	}
	t.Logf("udc2 relay: %s", relayAddr)

	// --- Beacon side ---
	beacon, err := turnc.Dial(ctx, turnc.Options{
		Host:     testTurnHost,
		PinnedIP: "127.0.0.1",
		Port:     turnPort,
		Username: testUser,
		Password: testPass,
		RootCAs:  certPool(t, cert),
	})
	if err != nil {
		t.Fatalf("beacon dial: %v", err)
	}
	defer beacon.Close()
	t.Logf("beacon relay: %s", beacon.RelayAddr())

	// The BOF creates a permission for the operator relay IP first.
	if err := beacon.Permit(&net.UDPAddr{IP: relayAddr.IP, Port: 0}); err != nil {
		t.Fatalf("beacon permit: %v", err)
	}

	// Build a fake Beacon frame and send it as chunks.
	frame := make([]byte, 4+8000)
	binary.LittleEndian.PutUint32(frame, 8000)
	for i := 4; i < len(frame); i++ {
		frame[i] = byte(i * 7)
	}
	const sessionID = 0x0badf00d
	for _, chunk := range proto.SplitMessage(sessionID, 0, frame, 1024) {
		if _, err := beacon.WriteTo(chunk, relayAddr); err != nil {
			t.Fatalf("beacon write chunk: %v", err)
		}
	}

	asm := proto.NewAssembler(1 << 20)
	buf := make([]byte, 64<<10)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for response")
		}
		beacon.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := beacon.ReadFrom(buf)
		if err != nil {
			t.Fatalf("beacon read: %v", err)
		}
		if !from.IP.Equal(relayAddr.IP) {
			continue
		}
		chunk, err := proto.ParseChunk(buf[:n])
		if err != nil {
			t.Fatalf("beacon parse chunk: %v", err)
		}
		msg, complete, err := asm.Push(chunk)
		if err != nil {
			t.Fatalf("beacon assemble: %v", err)
		}
		if complete {
			if len(msg) != len(frame) {
				t.Fatalf("response size mismatch: got %d want %d", len(msg), len(frame))
			}
			for i := range msg {
				if msg[i] != frame[i] {
					t.Fatalf("response mismatch at byte %d", i)
				}
			}
			t.Logf("round trip OK (%d bytes)", len(msg))
			return
		}
	}
}

// serveEchoTS accepts a UDC2 team server connection ("go" frame) and
// echoes every subsequent frame back.
func serveEchoTS(t *testing.T, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			first, err := readFrame(conn)
			if err != nil {
				t.Logf("[fakets] go frame read error: %v", err)
				return
			}
			if string(first[4:]) != "go" {
				t.Logf("[fakets] expected go, got %q", first)
				return
			}
			t.Logf("[fakets] session started")
			for {
				frame, err := readFrame(conn)
				if err != nil {
					t.Logf("[fakets] read error: %v", err)
					return
				}
				t.Logf("[fakets] frame in (%d bytes)", len(frame))
				if _, err := conn.Write(frame); err != nil {
					t.Logf("[fakets] write error: %v", err)
					return
				}
			}
		}()
	}
}

func selfSignedCert(t *testing.T, hosts ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func certPool(t *testing.T, cert tls.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	var pemBytes bytes.Buffer
	pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if !pool.AppendCertsFromPEM(pemBytes.Bytes()) {
		t.Fatal("failed to add cert to pool")
	}
	return pool
}
