// stun.c — see stun.h
#include "stun.h"
#include "crypto.h"

static void put_be16(unsigned char* p, unsigned short v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static unsigned short get_be16(const unsigned char* p) {
    return (unsigned short)((p[0] << 8) | p[1]);
}

static void put_be32(unsigned char* p, unsigned long v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static unsigned long get_be32(const unsigned char* p) {
    return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) |
           ((unsigned long)p[2] << 8) | (unsigned long)p[3];
}

void stun_start(STUN_MSG* m, unsigned short type, unsigned char* buf, unsigned long cap) {
    m->buf = buf;
    m->cap = cap;
    m->len = STUN_HEADER_SIZE;
    put_be16(m->buf + 0, type);
    put_be16(m->buf + 2, 0); // length (attrs only), fixed up as attrs are added
    put_be32(m->buf + 4, STUN_MAGIC_COOKIE);
    crypto_rand(m->buf + 8, 12); // transaction id
}

static void stun_fix_len(STUN_MSG* m) {
    put_be16(m->buf + 2, (unsigned short)(m->len - STUN_HEADER_SIZE));
}

int stun_attr(STUN_MSG* m, unsigned short type, const void* value, unsigned short valueLen) {
    unsigned long pad = (4 - (valueLen & 3)) & 3;
    if (m->len + 4 + valueLen + pad > m->cap) return -1;
    unsigned char* p = m->buf + m->len;
    put_be16(p + 0, type);
    put_be16(p + 2, valueLen);
    if (valueLen) bof_memcpy(p + 4, value, valueLen);
    if (pad) bof_memset(p + 4 + valueLen, 0, pad);
    m->len += 4 + valueLen + pad;
    stun_fix_len(m);
    return 0;
}

int stun_add_message_integrity(STUN_MSG* m, const unsigned char* key, unsigned long keyLen) {
    unsigned char hmac[20];
    unsigned long attrsLen = m->len - STUN_HEADER_SIZE;

    if (m->len + 24 > m->cap) return -1;

    // HMAC is computed over the message with the header length field set to
    // include the MESSAGE-INTEGRITY attribute itself (4 + 20).
    put_be16(m->buf + 2, (unsigned short)(attrsLen + 24));
    if (crypto_hmac_sha1(hmac, key, keyLen, m->buf, m->len) != 0) return -1;

    unsigned char* p = m->buf + m->len;
    put_be16(p + 0, STUN_ATTR_MESSAGE_INTEGRITY);
    put_be16(p + 2, 20);
    bof_memcpy(p + 4, hmac, 20);
    m->len += 24;
    stun_fix_len(m);
    return 0;
}

int stun_add_fingerprint(STUN_MSG* m) {
    unsigned long crc;
    unsigned long attrsLen = m->len - STUN_HEADER_SIZE;

    if (m->len + 8 > m->cap) return -1;

    // CRC-32 over the message with the length field set to include the
    // FINGERPRINT attribute (4 + 4), then XOR with the STUN magic value.
    put_be16(m->buf + 2, (unsigned short)(attrsLen + 8));
    crc = crypto_crc32(m->buf, m->len) ^ 0x5354554EUL;

    unsigned char* p = m->buf + m->len;
    put_be16(p + 0, STUN_ATTR_FINGERPRINT);
    put_be16(p + 2, 4);
    put_be32(p + 4, crc);
    m->len += 8;
    stun_fix_len(m);
    return 0;
}

const unsigned char* stun_find(const STUN_MSG* m, unsigned short type, unsigned short* valueLen) {
    unsigned long off = STUN_HEADER_SIZE;
    while (off + 4 <= m->len) {
        unsigned short at = get_be16(m->buf + off);
        unsigned short al = get_be16(m->buf + off + 2);
        unsigned long pad = (4 - (al & 3)) & 3;
        if (off + 4 + al > m->len) return NULL;
        if (at == type) {
            if (valueLen) *valueLen = al;
            return m->buf + off + 4;
        }
        off += 4 + al + pad;
    }
    return NULL;
}

void stun_write_xor_address(unsigned char out[8], unsigned long ip, unsigned short port) {
    // ip arrives in network byte order (from sin_addr.S_un.S_addr);
    // convert to the numerical value before XOR with the magic cookie.
    out[0] = 0x00; // reserved
    out[1] = 0x01; // IPv4
    put_be16(out + 2, (unsigned short)(port ^ 0x2112));
    put_be32(out + 4, htonl(ip) ^ STUN_MAGIC_COOKIE);
}

int stun_read_xor_address(const unsigned char v[8], unsigned long* ip, unsigned short* port) {
    if (v[1] != 0x01) return -1;
    *port = (unsigned short)(get_be16(v + 2) ^ 0x2112);
    *ip = htonl(get_be32(v + 4) ^ STUN_MAGIC_COOKIE); // return in network byte order
    return 0;
}

int stun_error_code(const STUN_MSG* m, int* code) {
    unsigned short vlen;
    const unsigned char* v = stun_find(m, STUN_ATTR_ERROR_CODE, &vlen);
    if (!v || vlen < 4) return -1;
    *code = (v[2] & 0x07) * 100 + v[3];
    return 0;
}
