// crypto.c — see crypto.h
#include "crypto.h"

// GCC may emit calls to memset/memcpy for struct copies and zero-init even
// with -fno-builtin; provide CRT-free definitions.
void* memset(void* d, int c, size_t n) { return bof_memset(d, c, n); }
void* memcpy(void* d, const void* s, size_t n) { return bof_memcpy(d, s, n); }

void* bof_memset(void* d, int c, size_t n) {
    unsigned char* p = (unsigned char*)d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}

void* bof_memcpy(void* d, const void* s, size_t n) {
    unsigned char* dp = (unsigned char*)d;
    const unsigned char* sp = (const unsigned char*)s;
    while (n--) *dp++ = *sp++;
    return d;
}

void* bof_memmove(void* d, const void* s, size_t n) {
    unsigned char* dp = (unsigned char*)d;
    const unsigned char* sp = (const unsigned char*)s;
    if (dp == sp || n == 0) return d;
    if (dp < sp) {
        while (n--) *dp++ = *sp++;
    } else {
        dp += n;
        sp += n;
        while (n--) *--dp = *--sp;
    }
    return d;
}

unsigned long bof_strlen(const char* s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

long bof_atoi(const char* s) {
    long v = 0;
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return neg ? -v : v;
}

#if defined(__i386__)
// On i386 GCC emits calls to libgcc's __udivdi3/__umoddi3 for 64-bit
// division and modulo — even by constants, because at -Os the libcall is
// smaller than the inline sequence. Cobalt Strike's UDC2 object loader
// cannot resolve libgcc symbols (one undefined ___udivdi3 fails the whole
// listener), while the debug test exe links libgcc normally and masks it.
// x64 divides natively, so these compile to nothing there.
static unsigned long long udivmod64(unsigned long long n, unsigned long long d,
                                    unsigned long long* rem) {
    unsigned long long q = 0, bit = 1;

    if (d == 0) { // divide by zero: return 0 rather than crash the payload
        if (rem) *rem = n;
        return 0;
    }
    while (!(d & 0x8000000000000000ULL) && d < n) {
        d <<= 1;
        bit <<= 1;
    }
    while (bit) {
        if (n >= d) {
            n -= d;
            q |= bit;
        }
        bit >>= 1;
        d >>= 1;
    }
    if (rem) *rem = n;
    return q;
}

unsigned long long __udivdi3(unsigned long long n, unsigned long long d) {
    return udivmod64(n, d, 0);
}

unsigned long long __umoddi3(unsigned long long n, unsigned long long d) {
    unsigned long long r;
    udivmod64(n, d, &r);
    return r;
}
#endif

int crypto_md5(unsigned char* out, const unsigned char* data, unsigned long len) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;
    int ok = -1;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (st != 0) goto done;
    st = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (st != 0) goto done;
    st = BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
    if (st != 0) goto done;
    st = BCryptFinishHash(hash, out, 16, 0);
    if (st != 0) goto done;
    ok = 0;

done:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

int crypto_hmac_sha1(unsigned char* out,
                     const unsigned char* key, unsigned long keyLen,
                     const unsigned char* data, unsigned long dataLen) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;
    int ok = -1;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != 0) goto done;
    st = BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)key, (ULONG)keyLen, 0);
    if (st != 0) goto done;
    st = BCryptHashData(hash, (PUCHAR)data, (ULONG)dataLen, 0);
    if (st != 0) goto done;
    st = BCryptFinishHash(hash, out, 20, 0);
    if (st != 0) goto done;
    ok = 0;

done:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

unsigned long crypto_crc32(const unsigned char* data, unsigned long len) {
    // Bitwise, reflected CRC-32 (poly 0xEDB88320), no table to save space.
    unsigned long crc = 0xFFFFFFFFUL;
    unsigned long i;
    int k;
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (k = 0; k < 8; k++) {
            unsigned long mask = -(crc & 1UL);
            crc = (crc >> 1) ^ (0xEDB88320UL & mask);
        }
    }
    return ~crc;
}

int crypto_rand(void* buf, unsigned long len) {
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
}
