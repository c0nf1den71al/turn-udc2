// crypto.h — minimal crypto for STUN/TURN: MD5, HMAC-SHA1, CRC32 and
// random bytes, all via bcrypt, with no CRT dependencies.
#ifndef BOF_CRYPTO_H
#define BOF_CRYPTO_H

#include "dfr.h"

void* bof_memset(void* d, int c, size_t n);
void* bof_memcpy(void* d, const void* s, size_t n);
void* bof_memmove(void* d, const void* s, size_t n);

// md5(out16, data, len)
int crypto_md5(unsigned char* out /*16*/, const unsigned char* data, unsigned long len);

unsigned long bof_strlen(const char* s);
long bof_atoi(const char* s);

// hmac_sha1(out20, key, keylen, data, datalen)
int crypto_hmac_sha1(unsigned char* out /*20*/,
                     const unsigned char* key, unsigned long keyLen,
                     const unsigned char* data, unsigned long dataLen);

// crc32(data, len) — standard (zlib) CRC-32.
unsigned long crypto_crc32(const unsigned char* data, unsigned long len);

// crypto_rand(buf, len) — system-preferred RNG.
int crypto_rand(void* buf, unsigned long len);

#endif
