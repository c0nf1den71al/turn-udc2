package turnc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/transport/v2/stdnet"
	"github.com/pion/turn/v2"
)

// TestSendIndicationDelivers guards against malformed hand-built STUN:
// a Send indication that lacks a proper header (type/magic cookie) is
// silently dropped by RFC 5389 servers.
func TestSendIndicationDelivers(t *testing.T) {
	netStack, err := stdnet.NewNet()
	if err != nil {
		t.Fatalf("stdnet: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: "turnc.test",
		AuthHandler: func(username, realm string, src net.Addr) ([]byte, bool) {
			return turn.GenerateAuthKey(username, realm, "pass"), true
		},
		InboundMTU: 65536,
		ListenerConfigs: []turn.ListenerConfig{{
			Listener: ln,
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
	defer srv.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a, err := Dial(ctx, Options{Host: "server.test", PinnedIP: "127.0.0.1", Port: port, Username: "u", Password: "pass", NoTLS: true})
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer a.Close()
	b, err := Dial(ctx, Options{Host: "server.test", PinnedIP: "127.0.0.1", Port: port, Username: "u", Password: "pass", NoTLS: true})
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer b.Close()

	if err := b.Permit(&net.UDPAddr{IP: a.RelayAddr().IP, Port: 0}); err != nil {
		t.Fatalf("permit B→A: %v", err)
	}
	// RFC 5766 §10.2: the sender also needs a permission for the peer
	// before its Send indications are relayed.
	if err := a.Permit(&net.UDPAddr{IP: b.RelayAddr().IP, Port: 0}); err != nil {
		t.Fatalf("permit A→B: %v", err)
	}

	payload := []byte("send indication regression")
	if err := a.SendIndication(b.RelayAddr(), payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	buf := make([]byte, 1500)
	b.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := b.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read (SendIndication was dropped?): %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload mismatch: %q", buf[:n])
	}
	if !from.IP.Equal(a.RelayAddr().IP) {
		t.Fatalf("peer mismatch: %v", from)
	}
}
