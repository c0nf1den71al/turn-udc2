// turn-probe validates the TURN infrastructure used by the TURN UDC2
// channel:
//
//	turn-probe                       fetch and display Teams TURN credentials
//	turn-probe -allocate 3           allocate N relays and print their addresses
//	turn-probe -hairpin              relay-to-relay data exchange test
//	turn-probe -simulate-beacon IP:PORT   full BOF simulation against a
//	                                     running turn-udc2-server relay
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jamiepegg/turn-c2/internal/msteams"
	"github.com/jamiepegg/turn-c2/internal/proto"
	"github.com/jamiepegg/turn-c2/internal/turnc"
)

func main() {
	var (
		turnServer   = flag.String("turn-server", msteams.DefaultServerHost+":"+fmt.Sprint(msteams.DefaultServerPort), "TURN server host:port (TURNS)")
		turnServerIP = flag.String("turn-server-ip", "", "pin TURN server IP")
		username     = flag.String("username", "", "TURN username (default: fetch anonymously from Teams)")
		password     = flag.String("password", "", "TURN password (default: fetch anonymously from Teams)")
		allocate     = flag.Int("allocate", 0, "allocate N relays and print their addresses")
		hairpin      = flag.Bool("hairpin", false, "relay-to-relay exchange test between two allocations")
		simulate     = flag.String("simulate-beacon", "", "simulate a BOF: send a UDC2 frame to the given relayed address of a running turn-udc2-server")
		blast        = flag.Bool("blast", false, "send raw Send indications between two allocations to diagnose burst behavior")
		blastCount   = flag.Int("blast-count", 74, "number of chunks for -blast")
		blastSize    = flag.Int("blast-size", 4096, "chunk payload size for -blast")
		blastPace    = flag.Duration("blast-pace", 0, "pause between chunks for -blast (e.g. 5ms)")
		frameSize    = flag.Int("frame-size", 300000, "frame size for -simulate-beacon")
		chunkSize    = flag.Int("chunk-size", 4096, "chunk size for -simulate-beacon")
		timeout      = flag.Duration("timeout", 60*time.Second, "overall timeout")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	user, pass := *username, *password
	if user == "" || pass == "" {
		creds, err := msteams.Fetch()
		if err != nil {
			log.Fatalf("credential fetch failed: %v", err)
		}
		user, pass = creds.Username, creds.Password
		if *allocate == 0 && !*hairpin && !*blast && *simulate == "" {
			// credentials-only mode
			fmt.Printf("realm:     %s\n", creds.Realm)
			fmt.Printf("username:  %s\n", creds.Username)
			fmt.Printf("password:  %s\n", creds.Password)
			fmt.Printf("expires:   %d\n", creds.Expires)
			if t, ok := creds.ExpiresAt(); ok {
				fmt.Printf("  (interpreted as %s)\n", t.Format(time.RFC3339))
			}
			if t, ok := creds.UsernameExpiry(); ok {
				fmt.Printf("username embeds expiry: %s\n", t.Format(time.RFC3339))
			}
			return
		}
	}

	host, portStr, err := net.SplitHostPort(*turnServer)
	if err != nil {
		log.Fatalf("bad --turn-server: %v", err)
	}
	port := 443
	if portStr != "" {
		if p, err := net.LookupPort("tcp", portStr); err == nil {
			port = p
		}
	}

	switch {
	case *hairpin:
		hairpinTest(ctx, host, port, *turnServerIP, user, pass)
	case *blast:
		blastTest(ctx, host, port, *turnServerIP, user, pass, *blastCount, *blastSize, *blastPace)
	case *simulate != "":
		simulateBeacon(ctx, host, port, *turnServerIP, user, pass, *simulate, *frameSize, *chunkSize)
	case *allocate > 0:
		allocateN(ctx, host, port, *turnServerIP, user, pass, *allocate)
	default:
		flag.Usage()
	}
}

func dial(ctx context.Context, host string, port int, pinnedIP, user, pass string) *turnc.Client {
	c, err := turnc.Dial(ctx, turnc.Options{
		Host:     host,
		PinnedIP: pinnedIP,
		Port:     port,
		Username: user,
		Password: pass,
	})
	if err != nil {
		log.Fatalf("TURN connect failed: %v", err)
	}
	return c
}

func allocateN(ctx context.Context, host string, port int, pinnedIP, user, pass string, n int) {
	seen := map[string]int{}
	for i := 0; i < n; i++ {
		c := dial(ctx, host, port, pinnedIP, user, pass)
		fmt.Printf("allocation %d: relay=%s server=%s\n", i+1, c.RelayAddr(), c.ServerAddr())
		seen[c.RelayAddr().IP.String()]++
		// leak intentionally (keep allocations distinct); close on exit
		defer c.Close()
	}
	fmt.Println("\nrelay IP pool observed:")
	for ip, count := range seen {
		fmt.Printf("  %s x%d\n", ip, count)
	}
}

func hairpinTest(ctx context.Context, host string, port int, pinnedIP, user, pass string) {
	a := dial(ctx, host, port, pinnedIP, user, pass)
	b := dial(ctx, host, port, pinnedIP, user, pass)
	defer a.Close()
	defer b.Close()

	fmt.Printf("A relay=%s server=%s\n", a.RelayAddr(), a.ServerAddr())
	fmt.Printf("B relay=%s server=%s\n", b.RelayAddr(), b.ServerAddr())

	// B must permit A's relay IP to receive from it; A's WriteTo installs
	// the permission for B's relay automatically.
	if err := b.Permit(&net.UDPAddr{IP: a.RelayAddr().IP, Port: 0}); err != nil {
		log.Fatalf("B CreatePermission(A relay ip): %v", err)
	}
	fmt.Println("[+] permissions installed")

	payload := []byte("turn-c2 hairpin test")
	if _, err := a.WriteTo(payload, b.RelayAddr()); err != nil {
		log.Fatalf("A write: %v", err)
	}

	buf := make([]byte, 4096)
	b.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, from, err := b.ReadFrom(buf)
	if err != nil {
		log.Fatalf("B read: %v (relay-to-relay delivery failed)", err)
	}
	fmt.Printf("[+] B received %q from %s\n", string(buf[:n]), from)

	if _, err := b.WriteTo(buf[:n], a.RelayAddr()); err != nil {
		log.Fatalf("B write: %v", err)
	}
	a.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, from, err = a.ReadFrom(buf)
	if err != nil {
		log.Fatalf("A read: %v", err)
	}
	fmt.Printf("[+] A received %q from %s\n", string(buf[:n]), from)
	fmt.Println("[+] hairpin relay-to-relay works on this TURN server")
}

// simulateBeacon acts like the BOF: allocate a relay, create a permission
// for the server relay IP, send a chunked frame to it, reassemble the
// response.
func simulateBeacon(ctx context.Context, host string, port int, pinnedIP, user, pass, target string, frameSize, chunkSize int) {
	targetAddr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		log.Fatalf("bad target: %v", err)
	}

	c := dial(ctx, host, port, pinnedIP, user, pass)
	defer c.Close()
	fmt.Printf("[*] beacon-side relay: %s (server %s)\n", c.RelayAddr(), c.ServerAddr())

	// The BOF creates a permission for the operator relay's IP before
	// sending (RFC 5766 10.1).
	if err := c.Permit(&net.UDPAddr{IP: targetAddr.IP, Port: 0}); err != nil {
		log.Fatalf("CreatePermission(target relay ip): %v", err)
	}

	// Build a fake Beacon frame: 4-byte LE length + random data.
	frame := make([]byte, 4+frameSize)
	binary.LittleEndian.PutUint32(frame, uint32(frameSize))
	if _, err := rand.Read(frame[4:]); err != nil {
		log.Fatalf("rand: %v", err)
	}

	var sessionID [4]byte
	rand.Read(sessionID[:])
	sid := binary.BigEndian.Uint32(sessionID[:])

	start := time.Now()
	chunks := proto.SplitMessage(sid, 0, frame, chunkSize)
	fmt.Printf("[*] sending frame of %d bytes as %d chunks (session %08x)\n", len(frame), len(chunks), sid)
	for _, ch := range chunks {
		if _, err := c.WriteTo(ch, targetAddr); err != nil {
			log.Fatalf("write chunk: %v", err)
		}
	}

	// Mirror of the BOF's ARQ: retransmit on request, request missing
	// response fragments when the stream stalls.
	asm := proto.NewAssembler(4 << 20)
	buf := make([]byte, 64<<10)
	const overallTimeout = 60 * time.Second
	const stallTimeout = 600 * time.Millisecond
	for {
		c.SetReadDeadline(time.Now().Add(stallTimeout))
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if time.Since(start) > overallTimeout {
				log.Fatalf("read response: %v", err)
			}
			if missing := asm.Missing(64); len(missing) > 0 {
				fmt.Printf("[*] requesting resend of %d fragments\n", len(missing))
				if _, err := c.WriteTo(proto.BuildResend(sid, asm.MsgSeq(), missing), targetAddr); err != nil {
					log.Fatalf("write resend: %v", err)
				}
			}
			continue
		}
		if !from.IP.Equal(targetAddr.IP) {
			continue
		}
		chunk, err := proto.ParseChunk(buf[:n])
		if err != nil {
			log.Printf("[-] bad chunk: %v", err)
			continue
		}
		switch chunk.Type {
		case proto.TypeResend:
			indices, err := proto.IndicesFromResend(chunk)
			if err != nil || chunk.MsgSeq != 0 {
				continue
			}
			for _, idx := range indices {
				if int(idx) < len(chunks) {
					c.WriteTo(chunks[idx], targetAddr)
				}
			}
		case proto.TypeData:
			msg, complete, err := asm.Push(chunk)
			if err != nil {
				log.Fatalf("reassemble: %v", err)
			}
			if complete {
				elapsed := time.Since(start)
				if len(msg) != len(frame) {
					log.Fatalf("response length mismatch: got %d want %d", len(msg), len(frame))
				}
				for i := range msg {
					if msg[i] != frame[i] {
						log.Fatalf("response data mismatch at byte %d", i)
					}
				}
				fmt.Printf("[+] round trip OK: %d bytes in %s (%d chunks)\n", len(msg), elapsed, len(chunks))
				return
			}
		}
	}
}

// blastTest sends N raw Send indications from allocation A to allocation B
// to isolate how the TURN server handles bursts (rate, size, pacing).
func blastTest(ctx context.Context, host string, port int, pinnedIP, user, pass string, count, size int, pace time.Duration) {
	a := dial(ctx, host, port, pinnedIP, user, pass)
	b := dial(ctx, host, port, pinnedIP, user, pass)
	defer a.Close()
	defer b.Close()

	fmt.Printf("A relay=%s server=%s\n", a.RelayAddr(), a.ServerAddr())
	fmt.Printf("B relay=%s server=%s\n", b.RelayAddr(), b.ServerAddr())

	if err := b.Permit(&net.UDPAddr{IP: a.RelayAddr().IP, Port: 0}); err != nil {
		log.Fatalf("B CreatePermission(A relay ip): %v", err)
	}
	if err := a.Permit(&net.UDPAddr{IP: b.RelayAddr().IP, Port: 0}); err != nil {
		log.Fatalf("A CreatePermission(B relay ip): %v", err)
	}

	fmt.Printf("[*] blasting %d raw Send indications of %d bytes (pace %s)\n", count, size, pace)

	// Receiver: counts delivered chunks; reports after 3s of inactivity.
	recvResult := make(chan int, 1)
	go func() {
		got := 0
		buf := make([]byte, 65536)
		b.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			n, _, err := b.ReadFrom(buf)
			if n > 0 {
				got++
			}
			if err != nil {
				recvResult <- got
				return
			}
			b.SetReadDeadline(time.Now().Add(3 * time.Second))
		}
	}()

	// Sender.
	sent := 0
	var sendErr error
	for i := 0; i < count; i++ {
		if err := a.SendIndication(b.RelayAddr(), bytes.Repeat([]byte{byte(i)}, size)); err != nil {
			sendErr = err
			break
		}
		sent++
		if pace > 0 {
			time.Sleep(pace)
		}
	}

	delivered := <-recvResult
	fmt.Printf("[*] sent %d/%d, delivered %d\n", sent, count, delivered)
	if sendErr != nil {
		fmt.Printf("[-] send error after %d chunks: %v\n", sent, sendErr)
	}
	if sent == count && delivered == count {
		fmt.Println("[+] relayed hop delivers raw Send indications cleanly")
	}
}
