package proto

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestChunkRoundTrip(t *testing.T) {
	payload := []byte("hello turn")
	encoded := AppendChunk(nil, Chunk{
		SessionID: 0xdeadbeef,
		Type:      TypeData,
		MsgSeq:    7,
		FragIndex: 2,
		FragTotal: 9,
		Payload:   payload,
	})

	c, err := ParseChunk(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.SessionID != 0xdeadbeef || c.Type != TypeData || c.MsgSeq != 7 || c.FragIndex != 2 || c.FragTotal != 9 {
		t.Fatalf("fields mismatch: %+v", c)
	}
	if !bytes.Equal(c.Payload, payload) {
		t.Fatalf("payload mismatch: %q", c.Payload)
	}
}

func TestParseChunkErrors(t *testing.T) {
	if _, err := ParseChunk(nil); err == nil {
		t.Fatal("expected error for empty buffer")
	}
	full := AppendChunk(nil, Chunk{SessionID: 1, Type: TypeData, FragIndex: 0, FragTotal: 1, Payload: []byte("ab")})
	if _, err := ParseChunk(full[:len(full)-1]); err == nil {
		t.Fatal("expected error for truncated payload")
	}
	bad := append([]byte{}, full...)
	bad[8] = 0 // frag_total high byte
	bad[9] = 0 // frag_total low byte → frag_total = 0
	if _, err := ParseChunk(bad); err == nil {
		t.Fatal("expected error for zero frag_total")
	}
	unknown := append([]byte{}, full...)
	unknown[4] = 9 // unknown type
	if _, err := ParseChunk(unknown); err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestSplitAndAssemble(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	msg := make([]byte, 100_000)
	rng.Read(msg)

	const sessionID = 0x11223344
	const maxPayload = 1024
	chunks := SplitMessage(sessionID, 3, msg, maxPayload)
	if len(chunks) != 98 {
		t.Fatalf("unexpected chunk count %d", len(chunks))
	}

	asm := NewAssembler(1 << 20)
	var got []byte
	for i, enc := range chunks {
		c, err := ParseChunk(enc)
		if err != nil {
			t.Fatalf("chunk %d parse: %v", i, err)
		}
		if c.SessionID != sessionID || c.MsgSeq != 3 {
			t.Fatalf("chunk %d header mismatch", i)
		}
		out, complete, err := asm.Push(c)
		if err != nil {
			t.Fatalf("chunk %d push: %v", i, err)
		}
		if complete != (i == len(chunks)-1) {
			t.Fatalf("chunk %d complete=%v", i, complete)
		}
		if complete {
			got = out
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("reassembled message differs from original")
	}
}

func TestAssemblerOutOfOrderAndLoss(t *testing.T) {
	msg := bytes.Repeat([]byte{0xAB}, 5000)
	chunks := SplitMessage(9, 0, msg, 1000) // 5 chunks

	asm := NewAssembler(1 << 20)
	// deliver 1,2,4 (lose 0 and 3)
	for _, i := range []int{1, 2, 4} {
		c, err := ParseChunk(chunks[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, complete, err := asm.Push(c); err != nil || complete {
			t.Fatalf("push %d: %v %v", i, err, complete)
		}
	}

	missing := asm.Missing(16)
	if len(missing) != 2 || missing[0] != 0 || missing[1] != 3 {
		t.Fatalf("expected [0 3], got %v", missing)
	}

	// deliver the missing fragments (in reverse for good measure)
	for _, i := range []int{3, 0} {
		c, _ := ParseChunk(chunks[i])
		out, complete, err := asm.Push(c)
		if err != nil {
			t.Fatalf("retransmit %d: %v", i, err)
		}
		if i == 0 {
			if !complete || !bytes.Equal(out, msg) {
				t.Fatal("expected complete message after retransmits")
			}
		} else if complete {
			t.Fatal("completed too early")
		}
	}
}

func TestAssemblerDuplicatesIgnored(t *testing.T) {
	chunks := SplitMessage(1, 0, bytes.Repeat([]byte{1}, 3000), 1000)
	asm := NewAssembler(1 << 20)
	c0, _ := ParseChunk(chunks[0])
	c0b, _ := ParseChunk(chunks[0])
	if _, _, err := asm.Push(c0); err != nil {
		t.Fatal(err)
	}
	if _, complete, err := asm.Push(c0b); err != nil || complete {
		t.Fatalf("duplicate: %v %v", err, complete)
	}
	if got := asm.Missing(8); len(got) != 2 {
		t.Fatalf("expected 2 missing, got %v", got)
	}
}

func TestAssemblerNewSeqRestarts(t *testing.T) {
	asm := NewAssembler(1 << 20)
	// partial message seq 0
	c, _ := ParseChunk(SplitMessage(1, 0, bytes.Repeat([]byte{9}, 2000), 1000)[0])
	if _, complete, err := asm.Push(c); err != nil || complete {
		t.Fatal("unexpected state")
	}
	// a new message (seq 1) with a single fragment must reset
	msg2 := []byte("fresh")
	c2, _ := ParseChunk(SplitMessage(1, 1, msg2, 1000)[0])
	out, complete, err := asm.Push(c2)
	if err != nil || !complete || string(out) != "fresh" {
		t.Fatalf("expected restart+complete, got %q %v %v", out, complete, err)
	}
}

func TestAssemblerMaxSize(t *testing.T) {
	asm := NewAssembler(16)
	// First message of exactly maxLen is allowed...
	c, _ := ParseChunk(SplitMessage(1, 0, bytes.Repeat([]byte{1}, 16), 16)[0])
	if _, _, err := asm.Push(c); err != nil {
		t.Fatalf("unexpected error on first chunk: %v", err)
	}
	// ...but a 32-byte message may not exceed maxLen.
	big := SplitMessage(1, 0, bytes.Repeat([]byte{2}, 32), 16)
	c0, _ := ParseChunk(big[0])
	if _, _, err := asm.Push(c0); err != nil {
		t.Fatalf("unexpected error on first big chunk: %v", err)
	}
	c1, _ := ParseChunk(big[1])
	if _, _, err := asm.Push(c1); err == nil {
		t.Fatal("expected size limit error")
	}
}

func TestResendRoundTrip(t *testing.T) {
	req := BuildResend(0x0a0b0c0d, 5, []uint16{3, 17, 65500})
	c, err := ParseChunk(req)
	if err != nil {
		t.Fatal(err)
	}
	indices, err := IndicesFromResend(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(indices) != 3 || indices[0] != 3 || indices[1] != 17 || indices[2] != 65500 {
		t.Fatalf("indices mismatch: %v", indices)
	}
	if c.MsgSeq != 5 || c.Type != TypeResend {
		t.Fatalf("header mismatch: %+v", c)
	}
}

func TestSplitMessageEmpty(t *testing.T) {
	chunks := SplitMessage(7, 2, nil, 128)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for empty message, got %d", len(chunks))
	}
	c, err := ParseChunk(chunks[0])
	if err != nil {
		t.Fatal(err)
	}
	out, complete, err := NewAssembler(16).Push(c)
	if err != nil || !complete {
		t.Fatal("expected complete empty message")
	}
	if len(out) != 0 {
		t.Fatalf("expected empty message, got %v", out)
	}
}
