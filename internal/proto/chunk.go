// Package proto defines the packet format carried inside TURN DATA
// attributes (Send/Data indications or ChannelData) between the UDC2 BOF
// on the Beacon and the UDC2 server.
//
// TURN-over-TLS-over-TCP is reliable on the client↔server legs, but the
// relayed hop between the two allocations is plain UDP (RFC 5766 always
// relays UDP) and drops packets in practice. The format therefore
// includes a simple ARQ: the receiver tracks gaps per message sequence
// number and asks the sender to RESEND specific fragments.
//
// Chunk layout (all integers big endian):
//
//	offset  0  uint32  session_id   random per-Beacon session identifier
//	offset  4  uint8   type         1 = DATA, 2 = RESEND
//	offset  5  uint8   msg_seq      per-message counter (wraps); a new
//	                                value restarts receiver state
//	offset  6  uint16  frag_index   0-based index of this fragment
//	offset  8  uint16  frag_total   total number of fragments in the message
//	offset 10  uint16  length       payload length in bytes
//	offset 12  bytes   payload      fragment bytes
//
// DATA payload: bytes of the Beacon frame (| 4-byte LE length | frame
// data |), split into fragments.
//
// RESEND payload: uint16 count followed by count fragment indices (each
// uint16, big endian) the receiver is missing for msg_seq.
//
// The BOF C implementation in bof/proto.c mirrors this format; keep the
// two in sync.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// ChunkHeaderSize is the size of the chunk header in bytes.
	ChunkHeaderSize = 12

	// MaxChunkPayload caps the payload of a single chunk. TURN over TCP
	// can carry messages up to ~64 KiB, but the relayed hop is a UDP
	// datagram: keep chunks small enough to avoid IP fragmentation
	// (fragments are commonly dropped).
	MaxChunkPayload = 1200

	// TypeData carries message fragments.
	TypeData uint8 = 1
	// TypeResend asks the peer to retransmit fragments.
	TypeResend uint8 = 2
)

// Chunk is one control or data message.
type Chunk struct {
	SessionID uint32
	Type      uint8
	MsgSeq    uint8
	FragIndex uint16
	FragTotal uint16
	Payload   []byte
}

// ParseChunk decodes a chunk from b.
func ParseChunk(b []byte) (Chunk, error) {
	var c Chunk
	if len(b) < ChunkHeaderSize {
		return c, errors.New("proto: chunk shorter than header")
	}
	c.SessionID = binary.BigEndian.Uint32(b[0:4])
	c.Type = b[4]
	c.MsgSeq = b[5]
	c.FragIndex = binary.BigEndian.Uint16(b[6:8])
	c.FragTotal = binary.BigEndian.Uint16(b[8:10])
	length := binary.BigEndian.Uint16(b[10:12])
	if int(length) != len(b)-ChunkHeaderSize {
		return c, fmt.Errorf("proto: chunk length %d does not match buffer %d", length, len(b)-ChunkHeaderSize)
	}
	switch c.Type {
	case TypeData:
		if c.FragTotal == 0 {
			return c, errors.New("proto: frag_total is zero")
		}
		if c.FragIndex >= c.FragTotal {
			return c, fmt.Errorf("proto: frag_index %d >= frag_total %d", c.FragIndex, c.FragTotal)
		}
	case TypeResend:
		// indices validated by IndicesFromResend
	default:
		return c, fmt.Errorf("proto: unknown chunk type %d", c.Type)
	}
	if length > 0 {
		// Copy: the caller's buffer is typically reused for the next
		// read, and chunks are processed asynchronously.
		payload := make([]byte, length)
		copy(payload, b[ChunkHeaderSize:])
		c.Payload = payload
	}
	return c, nil
}

// AppendChunk appends the wire encoding of c to dst and returns the
// extended buffer.
func AppendChunk(dst []byte, c Chunk) []byte {
	if len(c.Payload) > MaxChunkPayload {
		panic("proto: chunk payload exceeds MaxChunkPayload")
	}
	dst = append(dst,
		byte(c.SessionID>>24), byte(c.SessionID>>16), byte(c.SessionID>>8), byte(c.SessionID),
		byte(c.Type),
		byte(c.MsgSeq),
		byte(c.FragIndex>>8), byte(c.FragIndex),
		byte(c.FragTotal>>8), byte(c.FragTotal),
		byte(len(c.Payload)>>8), byte(len(c.Payload)),
	)
	return append(dst, c.Payload...)
}

// SplitMessage splits msg into a slice of encoded DATA chunks for the
// given session and message sequence number. maxPayload is the payload
// size of each chunk (clamped to MaxChunkPayload).
func SplitMessage(sessionID uint32, msgSeq uint8, msg []byte, maxPayload int) [][]byte {
	if maxPayload <= 0 || maxPayload > MaxChunkPayload {
		maxPayload = MaxChunkPayload
	}
	total := (len(msg) + maxPayload - 1) / maxPayload
	if total == 0 {
		total = 1
	}
	if total > 0xFFFF {
		panic("proto: message too large for fragmentation")
	}
	chunks := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		lo := i * maxPayload
		hi := lo + maxPayload
		if hi > len(msg) {
			hi = len(msg)
		}
		chunks = append(chunks, AppendChunk(nil, Chunk{
			SessionID: sessionID,
			Type:      TypeData,
			MsgSeq:    msgSeq,
			FragIndex: uint16(i),
			FragTotal: uint16(total),
			Payload:   msg[lo:hi],
		}))
	}
	return chunks
}

// BuildResend encodes a RESEND request for the given fragment indices of
// a message sequence number.
func BuildResend(sessionID uint32, msgSeq uint8, indices []uint16) []byte {
	payload := make([]byte, 2+2*len(indices))
	binary.BigEndian.PutUint16(payload, uint16(len(indices)))
	for i, idx := range indices {
		binary.BigEndian.PutUint16(payload[2+2*i:], idx)
	}
	return AppendChunk(nil, Chunk{
		SessionID: sessionID,
		Type:      TypeResend,
		MsgSeq:    msgSeq,
		Payload:   payload,
	})
}

// IndicesFromResend decodes the fragment indices carried by a RESEND
// chunk.
func IndicesFromResend(c Chunk) ([]uint16, error) {
	if c.Type != TypeResend {
		return nil, errors.New("proto: not a resend chunk")
	}
	p := c.Payload
	if len(p) < 2 {
		return nil, errors.New("proto: resend payload too short")
	}
	count := int(binary.BigEndian.Uint16(p[0:2]))
	if len(p) < 2+2*count {
		return nil, errors.New("proto: resend payload truncated")
	}
	indices := make([]uint16, count)
	for i := 0; i < count; i++ {
		indices[i] = binary.BigEndian.Uint16(p[2+2*i:])
	}
	return indices, nil
}

// Assembler reassembles messages from DATA chunks, tolerating (and
// tracking) gaps so the caller can issue RESEND requests. Order- and
// loss-insensitive: any fragment may arrive at any time. A DATA chunk
// whose msg_seq differs from the message in progress restarts the
// assembler.
type Assembler struct {
	maxLen    int
	sessionID uint32
	msgSeq    uint8
	fragTotal uint16
	received  []bool
	frags     [][]byte
	bytes     int
	count     int
}

// NewAssembler creates an assembler that refuses messages larger than
// maxLen bytes.
func NewAssembler(maxLen int) *Assembler {
	if maxLen <= 0 {
		maxLen = 4 << 20
	}
	return &Assembler{maxLen: maxLen}
}

// reset prepares the assembler for a new message.
func (a *Assembler) reset(c Chunk) {
	a.sessionID = c.SessionID
	a.msgSeq = c.MsgSeq
	a.fragTotal = c.FragTotal
	a.received = make([]bool, c.FragTotal)
	a.frags = make([][]byte, c.FragTotal)
	a.bytes = 0
	a.count = 0
}

// Push consumes one DATA chunk. It returns the completed message and true
// when the last missing fragment arrived. Duplicates are ignored.
func (a *Assembler) Push(c Chunk) (msg []byte, complete bool, err error) {
	if c.Type != TypeData {
		return nil, false, errors.New("proto: assembler expects data chunks")
	}
	if a.fragTotal == 0 || c.SessionID != a.sessionID || c.MsgSeq != a.msgSeq || c.FragTotal != a.fragTotal {
		a.reset(c)
	} else if c.FragIndex >= a.fragTotal {
		return nil, false, fmt.Errorf("proto: frag_index %d out of range", c.FragIndex)
	}

	if a.received[c.FragIndex] {
		return nil, false, nil // duplicate retransmission
	}

	a.bytes += len(c.Payload)
	if a.bytes > a.maxLen {
		a.fragTotal = 0
		return nil, false, fmt.Errorf("proto: reassembled message exceeds %d bytes", a.maxLen)
	}
	a.frags[c.FragIndex] = c.Payload
	a.received[c.FragIndex] = true
	a.count++

	if a.count >= int(a.fragTotal) {
		msg := make([]byte, 0, a.bytes)
		for _, frag := range a.frags {
			msg = append(msg, frag...)
		}
		a.fragTotal = 0
		a.received = nil
		a.frags = nil
		a.count = 0
		a.bytes = 0
		return msg, true, nil
	}
	return nil, false, nil
}

// Missing returns up to max indices of fragments that have not arrived yet
// (oldest first). Returns nil when nothing is missing or no message is
// in progress.
func (a *Assembler) Missing(max int) []uint16 {
	if a.fragTotal == 0 || a.count >= int(a.fragTotal) || max <= 0 {
		return nil
	}
	var missing []uint16
	for i := uint16(0); i < a.fragTotal; i++ {
		if !a.received[i] {
			missing = append(missing, i)
			if len(missing) >= max {
				break
			}
		}
	}
	return missing
}

// Active reports whether a message is mid-assembly.
func (a *Assembler) Active() bool { return a.fragTotal != 0 }

// MsgSeq returns the sequence of the message currently being reassembled.
func (a *Assembler) MsgSeq() uint8 { return a.msgSeq }

// SessionID returns the session of the message currently being reassembled,
// or 0 when idle.
func (a *Assembler) SessionID() uint32 { return a.sessionID }
