package turnc

import (
	"context"
	"crypto/md5"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/stun"
	"github.com/pion/turn/v2"
)

// Options configures a TURN client connection.
type Options struct {
	// Host is the TURN server hostname (SNI / certificate name).
	Host string
	// PinnedIP optionally replaces Host for the TCP connect address.
	PinnedIP string
	// Port is the TURN server port (443 for TURNS).
	Port int
	// Username/Password are the TURN long-term credentials.
	Username, Password string
	// NoTLS connects with plain TCP instead of TLS (testing).
	NoTLS bool
	// RootCAs overrides the root CA pool used to verify the server
	// certificate (nil = system roots).
	RootCAs *x509.CertPool
	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool
}

// Client is a convenience wrapper around pion/turn's client speaking
// TURN to a single server. It owns the connection, the pion client and
// one relay allocation.
type Client struct {
	conn       net.Conn
	client     *turn.Client
	relay      net.PacketConn
	relayAddr  *net.UDPAddr
	serverAddr net.Addr

	// Cached realm/nonce for raw authenticated transactions (see
	// authSession). TURN nonces are not bound to a username, so one
	// nonce serves any currently-valid credential pair.
	authMu    sync.Mutex
	authNonce string
	authRealm string
}

// Dial connects to the TURN server, authenticates with the given
// long-term credentials and allocates a relay. The TLS session and the
// allocation are kept alive by pion.
func Dial(ctx context.Context, o Options) (*Client, error) {
	connectHost := o.Host
	if o.PinnedIP != "" {
		connectHost = o.PinnedIP
	}
	addr := net.JoinHostPort(connectHost, fmt.Sprint(o.Port))

	var conn net.Conn
	var err error
	if o.NoTLS {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = DialTLS(ctx, o.Host, addr, &TLSOptions{
			RootCAs:            o.RootCAs,
			InsecureSkipVerify: o.InsecureSkipVerify,
		})
	}
	if err != nil {
		return nil, err
	}

	serverAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("resolve turn server addr: %w", err)
	}

	c := &Client{conn: conn, serverAddr: serverAddr}
	tap := &nonceTap{Conn: conn, c: c}

	client, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: serverAddr.String(),
		Username:       o.Username,
		Password:       o.Password,
		Conn:           turn.NewSTUNConn(tap),
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("turn client: %w", err)
	}
	if err := client.Listen(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("turn listen: %w", err)
	}
	c.client = client

	relay, err := client.Allocate()
	if err != nil {
		client.Close()
		conn.Close()
		return nil, fmt.Errorf("allocate: %w", err)
	}
	c.relay = relay

	var ok bool
	c.relayAddr, ok = relay.LocalAddr().(*net.UDPAddr)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("unexpected relay address type %T", relay.LocalAddr())
	}
	return c, nil
}

// nonceTap wraps the TLS connection to the TURN server and
// opportunistically caches the latest REALM/NONCE attributes seen in any
// inbound STUN message (pion's own allocate dance, nonce rotations in
// 401/438 responses, ...). Raw authenticated transactions — Refresh/
// CreatePermission with rotating credentials — stay in sync with the
// server's nonce state this way: Teams invalidates previously issued
// nonces when a new one is handed out, and its 438 responses carry no
// replacement nonce, so there is no other reliable way to recover one
// once an allocation is live.
type nonceTap struct {
	net.Conn
	c *Client
}

func (t *nonceTap) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.c.noteStun(b[:n])
	}
	return n, err
}

// noteStun scans a read buffer for STUN messages and caches any
// REALM/NONCE attributes found. Best-effort: buffers that start
// mid-message are skipped.
func (c *Client) noteStun(buf []byte) {
	off := 0
	for off+20 <= len(buf) {
		mtype := int(buf[off])<<8 | int(buf[off+1])
		mlen := int(buf[off+2])<<8 | int(buf[off+3])
		if mtype >= 0x4000 || // ChannelData; framing differs, bail out
			buf[off+4] != 0x21 || buf[off+5] != 0x12 || buf[off+6] != 0xA4 || buf[off+7] != 0x42 {
			return
		}
		end := off + 20 + mlen
		if end > len(buf) {
			return // truncated
		}
		var realm, nonce string
		p := off + 20
		for p+4 <= end {
			at := int(buf[p])<<8 | int(buf[p+1])
			al := int(buf[p+2])<<8 | int(buf[p+3])
			v := p + 4
			if v+al > end {
				break
			}
			switch at {
			case 0x0014: // REALM
				realm = string(buf[v : v+al])
			case 0x0015: // NONCE
				nonce = string(buf[v : v+al])
			}
			p = v + (al+3)&^3
		}
		if nonce != "" {
			c.authMu.Lock()
			c.authNonce = nonce
			if realm != "" {
				c.authRealm = realm
			}
			c.authMu.Unlock()
		}
		off = (end + 3) &^ 3 // TCP framing pads messages to 4 bytes
	}
}

// RelayAddr returns the relayed transport address of the allocation.
func (c *Client) RelayAddr() *net.UDPAddr { return c.relayAddr }

// ServerAddr returns the address of the TURN server the client is
// connected to.
func (c *Client) ServerAddr() net.Addr { return c.conn.RemoteAddr() }

// ReadFrom reads one application data packet received on the relay,
// returning the peer (relay) address it came from.
func (c *Client) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	for {
		n, from, err := c.relay.ReadFrom(b)
		if err != nil {
			return 0, nil, err
		}
		peer, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		return n, peer, err
	}
}

// WriteTo sends one application data packet to a peer address through the
// relay. pion installs/refreshes the permission for the destination
// automatically.
func (c *Client) WriteTo(b []byte, addr *net.UDPAddr) (int, error) {
	return c.relay.WriteTo(b, addr)
}

// Permit issues CreatePermission transactions for the given addresses.
func (c *Client) Permit(addrs ...net.Addr) error {
	return c.client.CreatePermission(addrs...)
}

// SendIndication writes a raw TURN Send indication carrying data to peer,
// bypassing pion's automatic permission/channel machinery (no ChannelBind,
// no transaction). Fire-and-forget like the BOF's sender.
func (c *Client) SendIndication(peer *net.UDPAddr, data []byte) error {
	// Must go through Build (not manual New()+Add): Build writes the STUN
	// header (type + magic cookie + txid) into Raw. Without it the message
	// carries a zero cookie and is silently dropped by RFC 5389 servers.
	msg := stun.New()
	if err := msg.Build(
		stun.NewType(stun.MethodSend, stun.ClassIndication),
		stun.TransactionID,
		rawAttr{xorPeerAddress, xorPeerValue(peer)},
		rawAttr{dataAttr, data},
		stun.Fingerprint,
	); err != nil {
		return err
	}
	_, err := c.client.WriteTo(msg.Raw, c.serverAddr)
	return err
}

// STUN attribute types used by SendIndication (pion/turn's proto package
// is internal, so encode the values directly).
const (
	xorPeerAddress         = 0x0012
	dataAttr               = 0x0013
	attrRequestedTransport = 0x0019
)

// rawAttr is a stun.Setter that appends one raw TLV.
type rawAttr struct {
	t stun.AttrType
	v []byte
}

func (a rawAttr) AddTo(m *stun.Message) error {
	m.Add(a.t, a.v)
	return nil
}

func xorPeerValue(a *net.UDPAddr) []byte {
	// [reserved=0][family=1][xport:2][xaddr:4], port^0x2112, addr^cookie
	ip := a.IP.To4()
	v := make([]byte, 8)
	v[1] = 0x01
	binary.BigEndian.PutUint16(v[2:4], uint16(a.Port)^0x2112)
	binary.BigEndian.PutUint32(v[4:8], binary.BigEndian.Uint32(ip)^0x2112A442)
	return v
}

// SetReadDeadline sets the read deadline on the relay allocation.
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.relay.SetReadDeadline(t)
}

// ---------------------------------------------------------------------
// Raw authenticated transactions with caller-supplied credentials.
//
// Teams TURN servers accept any currently-valid credential pair for
// transactions on an existing allocation (verified empirically: an
// allocation made with credentials A refreshes fine with freshly issued
// credentials B, and A keeps working afterwards). That is what makes
// runtime credential rotation possible without dropping the relay address
// baked into Beacons.
//
// The transactions are pumped through pion's PerformTransaction so the
// client's read loop stays the only reader of the connection.

type authSession struct {
	c            *Client
	username     string
	password     string
	realm, nonce string
}

func (a *authSession) key() []byte {
	sum := md5.Sum([]byte(a.username + ":" + a.realm + ":" + a.password))
	return sum[:]
}

func (a *authSession) build(method stun.Method, extra []stun.Setter) (*stun.Message, error) {
	attrs := append([]stun.Setter{stun.NewType(method, stun.ClassRequest), stun.TransactionID}, extra...)
	if a.nonce != "" {
		attrs = append(attrs,
			rawAttr{stun.AttrUsername, []byte(a.username)},
			rawAttr{stun.AttrRealm, []byte(a.realm)},
			rawAttr{stun.AttrNonce, []byte(a.nonce)},
			stun.MessageIntegrity(a.key()),
			stun.Fingerprint,
		)
	} else {
		attrs = append(attrs, stun.Fingerprint)
	}
	m := stun.New()
	if err := m.Build(attrs...); err != nil {
		return nil, fmt.Errorf("turnc: build %s: %w", method, err)
	}
	return m, nil
}

// prime obtains the realm and nonce needed to authenticate raw
// transactions via the unauthenticated ALLOCATE dance. Fallback for when
// Dial's harvest failed; only works while no allocation exists on the
// connection (Teams answers unauthenticated
// REFRESH/CreatePermission with 400, and ALLOCATE with 400 once an
// allocation is live). Never completes the ALLOCATE, so it disturbs
// nothing.
func (a *authSession) prime() error {
	attrs := []stun.Setter{
		stun.NewType(stun.MethodAllocate, stun.ClassRequest),
		stun.TransactionID,
		rawAttr{attrRequestedTransport, []byte{17, 0, 0, 0}},
		stun.Fingerprint,
	}
	m := stun.New()
	if err := m.Build(attrs...); err != nil {
		return fmt.Errorf("turnc: prime: %w", err)
	}
	res, err := a.c.client.PerformTransaction(m, a.c.serverAddr, false)
	if err != nil {
		return fmt.Errorf("turnc: prime: %w", err)
	}
	code, realm, nonce := errCodeRealmNonce(res.Msg)
	if nonce != "" {
		a.realm, a.nonce = realm, nonce
		a.c.authMu.Lock()
		a.c.authRealm, a.c.authNonce = realm, nonce
		a.c.authMu.Unlock()
		return nil
	}
	return fmt.Errorf("turnc: prime: ALLOCATE dance gave no nonce (code %d)", code)
}

// transact sends one request and handles the 401/438 realm/nonce dance.
func (a *authSession) transact(method stun.Method, extra []stun.Setter) (*stun.Message, error) {
	a.c.authMu.Lock()
	a.realm, a.nonce = a.c.authRealm, a.c.authNonce
	a.c.authMu.Unlock()

	for attempt := 0; attempt < 4; attempt++ {
		if a.nonce == "" {
			if err := a.prime(); err != nil {
				return nil, err
			}
		}
		m, err := a.build(method, extra)
		if err != nil {
			return nil, err
		}
		res, err := a.c.client.PerformTransaction(m, a.c.serverAddr, false)
		if err != nil {
			return nil, fmt.Errorf("turnc: %s transaction: %w", method, err)
		}
		resp := res.Msg
		if resp.Type.Class != stun.ClassErrorResponse {
			return resp, nil
		}
		code, realm, nonce := errCodeRealmNonce(resp)
		if code == 401 || code == 438 {
			if nonce != "" {
				a.realm, a.nonce = realm, nonce
				a.c.authMu.Lock()
				a.c.authRealm, a.c.authNonce = realm, nonce
				a.c.authMu.Unlock()
				continue
			}
			a.nonce = "" // response carried no nonce: re-prime
			continue
		}
		return nil, fmt.Errorf("turnc: %s error response %d", method, code)
	}
	return nil, fmt.Errorf("turnc: %s kept failing authentication", method)
}

func errCodeRealmNonce(m *stun.Message) (code int, realm, nonce string) {
	if v, err := m.Get(stun.AttrErrorCode); err == nil && len(v) >= 4 {
		code = int(v[2]&0x07)*100 + int(v[3])
	}
	if v, err := m.Get(stun.AttrRealm); err == nil {
		realm = string(v)
	}
	if v, err := m.Get(stun.AttrNonce); err == nil {
		nonce = string(v)
	}
	return code, realm, nonce
}

// RefreshAllocationWithCreds sends a REFRESH with the given credentials,
// extending the allocation lifetime (server default). The credentials
// may differ from the ones the client was created with.
func (c *Client) RefreshAllocationWithCreds(username, password string) error {
	a := &authSession{c: c, username: username, password: password}
	_, err := a.transact(stun.MethodRefresh, nil)
	return err
}

// PermitWithCreds issues CreatePermission transactions for the given IPs
// with the given credentials (port 0; TURN permissions are per IP).
// Batches addresses to keep messages small.
func (c *Client) PermitWithCreds(username, password string, ips ...net.IP) error {
	const batch = 4
	a := &authSession{c: c, username: username, password: password}
	for i := 0; i < len(ips); i += batch {
		end := i + batch
		if end > len(ips) {
			end = len(ips)
		}
		attrs := make([]stun.Setter, 0, end-i)
		for _, ip := range ips[i:end] {
			if ip4 := ip.To4(); ip4 != nil {
				attrs = append(attrs, rawAttr{xorPeerAddress, ipPermValue(ip4)})
			}
		}
		if len(attrs) == 0 {
			continue
		}
		if _, err := a.transact(stun.MethodCreatePermission, attrs); err != nil {
			return fmt.Errorf("create permission (batch at %d): %w", i, err)
		}
	}
	return nil
}

// ipPermValue encodes an XOR-PEER-ADDRESS for port 0 (permissions are
// per-IP; the port is ignored).
func ipPermValue(ip net.IP) []byte {
	v := make([]byte, 8)
	v[1] = 0x01
	binary.BigEndian.PutUint16(v[2:4], 0x2112) // port 0 ^ cookie
	binary.BigEndian.PutUint32(v[4:8], binary.BigEndian.Uint32(ip)^0x2112A442)
	return v
}

// Close releases the allocation and the connection.
func (c *Client) Close() {
	if c.relay != nil {
		c.relay.Close()
	}
	if c.client != nil {
		c.client.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}
