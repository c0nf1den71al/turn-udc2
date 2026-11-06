// proto.c — see proto.h
#include "proto.h"
#include "crypto.h"
#include "bof_config.h"

static unsigned char gChunkOut[TURN_CHUNK_SIZE + CHUNK_HEADER];
static unsigned char gChunkIn[65536 + CHUNK_HEADER];
static unsigned char gResend[CHUNK_HEADER + 2 + 2 * PROTO_MAX_MISSING];

// Transmission state for retransmission (one outstanding frame per call).
static struct {
    const unsigned char* frame;
    unsigned long frameLen;
    unsigned short total;
    unsigned char msgSeq;
    unsigned long session;
} gTx;

static void be16(unsigned char* p, unsigned short v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static void be32(unsigned char* p, unsigned long v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static unsigned long rdbe32(const unsigned char* p) {
    return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) |
           ((unsigned long)p[2] << 8) | (unsigned long)p[3];
}

static unsigned short rdbe16(const unsigned char* p) {
    return (unsigned short)((p[0] << 8) | p[1]);
}

// ------------------------------------------------------------------ sending

static int build_and_send_chunk(TURN_CTX* t, unsigned long session,
                                unsigned char msgSeq, unsigned long idx,
                                unsigned long total,
                                const unsigned char* payload, unsigned long len) {
    be32(gChunkOut, session);
    gChunkOut[4] = CHUNK_TYPE_DATA;
    gChunkOut[5] = msgSeq;
    be16(gChunkOut + 6, (unsigned short)idx);
    be16(gChunkOut + 8, (unsigned short)total);
    be16(gChunkOut + 10, (unsigned short)len);
    if (len) bof_memcpy(gChunkOut + CHUNK_HEADER, payload, len);
    return turn_send_data(t, gChunkOut, (unsigned short)(CHUNK_HEADER + len));
}

int proto_send_frame(TURN_CTX* t, unsigned long session, unsigned char msgSeq,
                     const unsigned char* frame, unsigned long frameLen) {
    unsigned long total, i, off;

    if (frameLen == 0) return -1;
    total = (frameLen + TURN_CHUNK_SIZE - 1) / TURN_CHUNK_SIZE;
    if (total > 0xFFFF) return -1;

    gTx.frame = frame;
    gTx.frameLen = frameLen;
    gTx.total = (unsigned short)total;
    gTx.msgSeq = msgSeq;
    gTx.session = session;

    for (i = 0, off = 0; i < total; i++, off += TURN_CHUNK_SIZE) {
        unsigned long n = frameLen - off;
        if (n > TURN_CHUNK_SIZE) n = TURN_CHUNK_SIZE;
        if (build_and_send_chunk(t, session, msgSeq, i, total, frame + off, n) != 0) {
            return -1;
        }
    }
    return 0;
}

// Re-sends the requested fragments of the outgoing frame.
static int proto_handle_resend(TURN_CTX* t, const unsigned char* payload, unsigned long payloadLen) {
    unsigned long count, k;

    if (payloadLen < 2) return 0;
    count = rdbe16(payload);
    if (payloadLen < 2 + 2 * count) return 0;
    for (k = 0; k < count; k++) {
        unsigned long idx = rdbe16(payload + 2 + 2 * k);
        unsigned long off, n;
        if (idx >= gTx.total) continue;
        off = idx * TURN_CHUNK_SIZE;
        n = gTx.frameLen - off;
        if (n > TURN_CHUNK_SIZE) n = TURN_CHUNK_SIZE;
        if (build_and_send_chunk(t, gTx.session, gTx.msgSeq, idx, gTx.total,
                                 gTx.frame + off, n) != 0) {
            return -1;
        }
    }
    return 0;
}

// ------------------------------------------------------------ receiving

static void asm_reset(CHUNK_ASM* a, unsigned long session, unsigned char msgSeq,
                      unsigned short fragTotal) {
    if (a->recv) VirtualFree(a->recv, 0, MEM_RELEASE);
    if (a->lastFrag) VirtualFree(a->lastFrag, 0, MEM_RELEASE);
    a->recv = (unsigned char*)VirtualAlloc(NULL, fragTotal, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    a->session = session;
    a->msgSeq = msgSeq;
    a->fragTotal = fragTotal;
    a->fragSize = 0;
    a->lastFrag = NULL;
    a->lastFragLen = 0;
    a->count = 0;
    a->bytes = 0;
    a->bufLen = 0; // buffer stays allocated
}

static int asm_reserve(CHUNK_ASM* a, unsigned long need) {
    unsigned char* fresh;
    unsigned long newCap;

    if (a->bufCap >= need) return 0;
    if (need > (unsigned long)TURN_MAX_FRAME) return -1;
    newCap = a->bufCap ? a->bufCap : 4096;
    while (newCap < need) newCap *= 2;
    if (newCap > (unsigned long)TURN_MAX_FRAME) newCap = (unsigned long)TURN_MAX_FRAME;

    fresh = (unsigned char*)VirtualAlloc(NULL, newCap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fresh) return -1;
    if (a->bufLen) bof_memcpy(fresh, a->buf, a->bufLen);
    if (a->buf) VirtualFree(a->buf, 0, MEM_RELEASE);
    a->buf = fresh;
    a->bufCap = newCap;
    return 0;
}

// Copies payload into the reassembly buffer at off.
static int asm_place(CHUNK_ASM* a, const unsigned char* payload, unsigned long len, unsigned long off) {
    if (off + len > (unsigned long)TURN_MAX_FRAME) return -1;
    if (asm_reserve(a, off + len) != 0) return -1;
    if (len) bof_memcpy(a->buf + off, payload, len);
    if (off + len > a->bufLen) a->bufLen = off + len;
    return 0;
}

// Pushes one DATA fragment; returns 1 when the message completed (in
// a->buf with a->bufLen bytes), 0 when incomplete, -1 on error.
static int asm_push(CHUNK_ASM* a, unsigned long session, unsigned char msgSeq,
                    unsigned long idx, unsigned long total,
                    const unsigned char* payload, unsigned long len) {
    unsigned long off;

    if (a->fragTotal == 0 || a->session != session || a->msgSeq != msgSeq ||
        a->fragTotal != total) {
        asm_reset(a, session, msgSeq, (unsigned short)total);
        if (!a->recv) return -1;
    }

    if (idx >= a->fragTotal) return -1;
    if (a->recv[idx]) return 0; // duplicate retransmission
    a->bytes += len;
    if (a->bytes > (unsigned long)TURN_MAX_FRAME) {
        a->fragTotal = 0;
        return -1;
    }

    if (idx + 1 < a->fragTotal) {
        // Non-final fragment: its length fixes the layout.
        if (a->fragSize == 0) {
            a->fragSize = len;
            // A final fragment stashed earlier can now be placed.
            if (a->lastFrag) {
                if (asm_place(a, a->lastFrag, a->lastFragLen, a->fragSize * (a->fragTotal - 1)) != 0) {
                    a->fragTotal = 0;
                    return -1;
                }
                VirtualFree(a->lastFrag, 0, MEM_RELEASE);
                a->lastFrag = NULL;
            }
        } else if (len != a->fragSize) {
            return -1; // sender must use uniform fragment sizes
        }
        off = idx * a->fragSize;
        if (asm_place(a, payload, len, off) != 0) {
            a->fragTotal = 0;
            return -1;
        }
    } else {
        // Final fragment.
        if (a->fragTotal == 1) {
            if (asm_place(a, payload, len, 0) != 0) {
                a->fragTotal = 0;
                return -1;
            }
        } else if (a->fragSize != 0) {
            if (asm_place(a, payload, len, a->fragSize * (a->fragTotal - 1)) != 0) {
                a->fragTotal = 0;
                return -1;
            }
        } else {
            // Layout not known yet: stash a copy.
            if (a->lastFrag) VirtualFree(a->lastFrag, 0, MEM_RELEASE);
            a->lastFrag = (unsigned char*)VirtualAlloc(NULL, len ? len : 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!a->lastFrag) {
                a->fragTotal = 0;
                return -1;
            }
            if (len) bof_memcpy(a->lastFrag, payload, len);
            a->lastFragLen = len;
        }
    }

    a->recv[idx] = 1;
    a->count++;

    if (a->count >= a->fragTotal && !a->lastFrag) {
        a->fragTotal = 0;
        return 1;
    }
    return 0;
}

// Builds a RESEND request for missing fragments; returns the payload length
// or 0 when nothing is missing.
static unsigned long asm_missing(CHUNK_ASM* a) {
    unsigned long i, count = 0;
    unsigned char* p = gResend + CHUNK_HEADER;

    if (a->fragTotal == 0 || !a->recv) return 0;
    for (i = 0; i < a->fragTotal && count < PROTO_MAX_MISSING; i++) {
        if (!a->recv[i]) {
            be16(p + 2 * count, (unsigned short)i);
            count++;
        }
    }
    if (count == 0) return 0;
    be16(p, (unsigned short)count);
    return 2 + 2 * count;
}

int proto_recv_frame(TURN_CTX* t, CHUNK_ASM* a, unsigned long session,
                     unsigned long long deadline,
                     unsigned char** out, unsigned long* outLen) {
    for (;;) {
        unsigned long got = 0;
        unsigned long cs, idx, total, clen;
        unsigned char type, seq;
        unsigned long long stallDeadline;
        int r;

        // Wait at most PROTO_STALL_MS at a time so gaps trigger RESEND
        // requests instead of a full-deadline stall.
        stallDeadline = GetTickCount64() + PROTO_STALL_MS;
        if (stallDeadline > deadline) stallDeadline = deadline;

        r = turn_recv_data(t, gChunkIn, sizeof(gChunkIn), &got, stallDeadline);
        if (r < 0) return -1;
        if (r == 0) {
            if (GetTickCount64() >= deadline) return 0;
            // Stalled with gaps? Ask for the missing fragments.
            if (a->fragTotal != 0) {
                unsigned long plen = asm_missing(a);
                if (plen > 0) {
                    be32(gResend, session);
                    gResend[4] = CHUNK_TYPE_RESEND;
                    gResend[5] = a->msgSeq;
                    be16(gResend + 6, 0);
                    be16(gResend + 8, 0);
                    be16(gResend + 10, (unsigned short)plen);
                    if (turn_send_data(t, gResend, (unsigned short)(CHUNK_HEADER + plen)) != 0) {
                        return -1;
                    }
                }
            }
            continue;
        }

        if (got < CHUNK_HEADER) continue;

        cs = rdbe32(gChunkIn);
        type = gChunkIn[4];
        seq = gChunkIn[5];
        idx = rdbe16(gChunkIn + 6);
        total = rdbe16(gChunkIn + 8);
        clen = rdbe16(gChunkIn + 10);
        if ((unsigned long)clen != got - CHUNK_HEADER) continue;
        if (cs != session) continue;

        if (type == CHUNK_TYPE_RESEND) {
            if (proto_handle_resend(t, gChunkIn + CHUNK_HEADER, clen) != 0) return -1;
            continue;
        }
        if (type != CHUNK_TYPE_DATA) continue;
        if (total == 0 || idx >= total) continue;

        r = asm_push(a, session, seq, idx, total, gChunkIn + CHUNK_HEADER, clen);
        if (r < 0) return -1;
        if (r == 1) {
            *out = a->buf;
            *outLen = a->bufLen;
            return 1;
        }
    }
}

void proto_asm_free(CHUNK_ASM* a) {
    if (a->buf) VirtualFree(a->buf, 0, MEM_RELEASE);
    if (a->recv) VirtualFree(a->recv, 0, MEM_RELEASE);
    if (a->lastFrag) VirtualFree(a->lastFrag, 0, MEM_RELEASE);
    a->buf = NULL;
    a->recv = NULL;
    a->lastFrag = NULL;
    a->bufCap = 0;
    a->bufLen = 0;
    a->fragTotal = 0;
}
