// turn-udc2-fakets is a fake Cobalt Strike team server UDC2 listener for
// testing the TURN UDC2 path without a real team server. It speaks the
// UDC2 wire protocol (initial "go" frame, then length-prefixed frames)
// and echoes every frame back to the client.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
)

func main() {
	var (
		bindAddr = flag.String("bind-addr", "127.0.0.1", "bind address")
		bindPort = flag.Int("bind-port", 2222, "bind port (team server UDC2 listener port)")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ln, err := net.Listen("tcp", net.JoinHostPort(*bindAddr, fmt.Sprint(*bindPort)))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("[*] fake team server (UDC2 echo) listening on %s", ln.Addr())
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[-] accept: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	log.Printf("[+] connection from %s", conn.RemoteAddr())

	// initial "go" frame
	first, err := readFrame(conn)
	if err != nil {
		log.Printf("[-] %s: read go frame: %v", conn.RemoteAddr(), err)
		return
	}
	if string(first[4:]) != "go" {
		log.Printf("[-] %s: expected go frame, got %q", conn.RemoteAddr(), first[4:])
		return
	}
	log.Printf("[+] %s: session started", conn.RemoteAddr())

	for {
		frame, err := readFrame(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("[-] %s: read: %v", conn.RemoteAddr(), err)
			}
			log.Printf("[*] %s: closed", conn.RemoteAddr())
			return
		}
		log.Printf("[*] %s: frame in (%d bytes), echoing", conn.RemoteAddr(), len(frame))
		if _, err := conn.Write(frame); err != nil {
			log.Printf("[-] %s: write: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

func readFrame(conn net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(lenBuf[:])
	if length > 16<<20 {
		return nil, fmt.Errorf("frame length %d too large", length)
	}
	frame := make([]byte, 4+length)
	copy(frame, lenBuf[:])
	if _, err := io.ReadFull(conn, frame[4:]); err != nil {
		return nil, err
	}
	return frame, nil
}
