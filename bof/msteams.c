// msteams.c — see msteams.h
//
// The flow mirrors internal/msteams/creds.go (adapted from
// praetorian-inc/turnt): POST the anonymous visitor endpoint to mint a
// Skype token, then GET the trap-exp tokens endpoint with it. Both
// requests send "Accept-Encoding: identity" (verified honored) so the
// JSON bodies arrive uncompressed.
#include "msteams.h"
#include "bof_config.h"
#include "schannel.h"
#include "crypto.h"

#ifdef TURN_DEBUG
#include <stdio.h>
#define DBG(fmt, ...) fprintf(stderr, "[*] " fmt, ##__VA_ARGS__)
#define DBG_ERR(fmt, ...) fprintf(stderr, "[-] " fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)
#define DBG_ERR(fmt, ...)
#endif

#define TEAMS_API_HOST "teams.microsoft.com"
#define TEAMS_API_PORT 443
#define TEAMS_UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36"

// Static staging: one credential fetch runs at a time in a BOF.
static TLS_CTX gApiTls;
static SOCKET gApiSock = INVALID_SOCKET;
static unsigned char gHttpBuf[16384];
static char gReq[2048];
static char gToken[1024];

unsigned long long msteams_now_unix(void) {
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    // FILETIME: 100ns ticks since 1601-01-01.
    return u.QuadPart / 10000000ULL - 11644473600ULL;
}

// ------------------------------------------------------------- string utils

static unsigned long sappend(char* dst, unsigned long cap, unsigned long used,
                             const char* src) {
    unsigned long i = 0;
    while (src[i] && used + i + 1 < cap) {
        dst[used + i] = src[i];
        i++;
    }
    dst[used + i] = 0;
    return used + i;
}

static int startswith(const char* s, const char* prefix) {
    unsigned long i = 0;
    while (prefix[i]) {
        if (s[i] != prefix[i]) return 0;
        i++;
    }
    return 1;
}

// Case-insensitive header lookup in a block of raw header bytes.
static int header_value(const char* headers, const char* name, char* out, unsigned long cap) {
    unsigned long i = 0, n = 0, ni = 0;
    char lower[64];

    while (name[ni] && ni < sizeof(lower) - 1) {
        char c = name[ni];
        if (c >= 'A' && c <= 'Z') c += 32;
        lower[ni++] = c;
    }
    lower[ni] = 0;

    while (headers[i]) {
        // At a header start: does it match (followed by ':')?
        unsigned long j = i, k = 0;
        while (headers[j] && headers[j] != '\r' && headers[j] != ':' && k < sizeof(lower) - 1) {
            char c = headers[j];
            if (c >= 'A' && c <= 'Z') c += 32;
            if (c != lower[k]) break;
            j++;
            k++;
        }
        if (headers[j] == ':' && lower[k] == 0) {
            j++;
            while (headers[j] == ' ' || headers[j] == '\t') j++;
            n = 0;
            while (headers[j] && headers[j] != '\r' && n + 1 < cap) {
                out[n++] = headers[j++];
            }
            out[n] = 0;
            return 1;
        }
        while (headers[i] && headers[i] != '\n') i++;
        if (headers[i]) i++;
    }
    return 0;
}

// ------------------------------------------------------------------- http

static void api_close(void) {
    tls_close(&gApiTls);
    if (gApiSock != INVALID_SOCKET && gApiSock != 0) closesocket(gApiSock);
    gApiSock = INVALID_SOCKET;
}

// Resolves, TCP-connects and TLS-connects to teams.microsoft.com:443.
static int api_connect(unsigned long long deadline) {
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* p;
    DWORD timeout = TURN_IO_TIMEOUT_MS;
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;

    bof_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(TEAMS_API_HOST, NULL, &hints, &res) != 0 || !res) return -1;

    gApiSock = INVALID_SOCKET;
    for (p = res; p; p = p->ai_next) {
        struct sockaddr_in addr;
        if (p->ai_family != AF_INET) continue;
        bof_memcpy(&addr, p->ai_addr, sizeof(addr));
        addr.sin_port = htons(TEAMS_API_PORT);

        gApiSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (gApiSock == INVALID_SOCKET) continue;
        if (setsockopt(gApiSock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0 ||
            setsockopt(gApiSock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) != 0 ||
            connect(gApiSock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            closesocket(gApiSock);
            gApiSock = INVALID_SOCKET;
            continue;
        }
        break;
    }
    freeaddrinfo(res);
    if (gApiSock == INVALID_SOCKET) return -1;

    if (tls_connect(&gApiTls, gApiSock, TEAMS_API_HOST, deadline) != 0) {
        api_close();
        return -1;
    }
    return 0;
}

// Reads one CRLF-terminated line (without the terminator) into out.
static int read_line(TLS_CTX* tls, char* out, unsigned long cap, unsigned long long deadline) {
    unsigned long n = 0;
    while (n + 1 < cap) {
        char c;
        if (tls_read_exact(tls, &c, 1, deadline) != 0) return -1;
        if (c == '\n') {
            if (n && out[n - 1] == '\r') n--;
            out[n] = 0;
            return 0;
        }
        out[n++] = c;
    }
    out[n] = 0;
    return 0;
}

// Reads exactly len body bytes into out (bounded by what is left of buf).
static int read_body_exact(TLS_CTX* tls, unsigned char* out, unsigned long cap,
                           unsigned long len, unsigned long* outLen,
                           unsigned long long deadline) {
    if (len > cap) return -1;
    if (len && tls_read_exact(tls, out, len, deadline) != 0) return -1;
    *outLen = len;
    return 0;
}

// Reads a chunked body per RFC 9112 section 7.1 (chunk sizes are hex).
static int read_body_chunked(TLS_CTX* tls, unsigned char* out, unsigned long cap,
                            unsigned long* outLen, unsigned long long deadline) {
    char line[32];
    unsigned long total = 0;

    for (;;) {
        unsigned long size = 0;
        unsigned long i, d;
        if (read_line(tls, line, sizeof(line), deadline) != 0) return -1;
        for (i = 0; ; i++) {
            char c = line[i];
            if (c >= '0' && c <= '9') d = (unsigned long)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (unsigned long)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = (unsigned long)(c - 'A' + 10);
            else break;
            if (size > (cap >> 4)) return -1; // overflow guard
            size = size * 16 + d;
        }
        if (i == 0) return -1; // empty chunk-size line
        if (line[i] != 0 && line[i] != ';') return -1; // extensions not expected
        if (size == 0) break;
        if (total + size > cap) return -1;
        if (tls_read_exact(tls, out + total, size, deadline) != 0) return -1;
        total += size;
        // Trailing CRLF after each chunk.
        if (read_line(tls, line, sizeof(line), deadline) != 0) return -1;
        if (line[0] != 0) return -1;
    }
    *outLen = total;
    return 0;
}

// Reads until the server closes (no Content-Length, no chunking).
static int read_body_until_eof(TLS_CTX* tls, unsigned char* out, unsigned long cap,
                               unsigned long* outLen, unsigned long long deadline) {
    unsigned long total = 0;
    while (total < cap) {
        char c;
        if (tls_read_exact(tls, &c, 1, deadline) != 0) break; // EOF or timeout
        out[total++] = (unsigned char)c;
    }
    if (total == cap) return -1; // no framing and no EOF: refuse to guess
    *outLen = total;
    return 0;
}

// Sends the request and reads the response body into out. extraHeaders is
// zero or more "Name: value\r\n" lines. Returns 0 on HTTP 200. The
// connection is left open; api_close is the caller's job on both paths.
// Each request gets a bounded deadline so a dead API path cannot eat the
// whole proxy-call deadline.
static int http_roundtrip(const char* method, const char* path, const char* extraHeaders,
                          unsigned char* out, unsigned long cap, unsigned long* outLen,
                          unsigned long long deadline) {
    char line[256];
    char headers[2048];
    char val[64];
    unsigned long hl = 0;
    int status = 0;

    if (api_connect(deadline) != 0) return -1;

    hl = sappend(gReq, sizeof(gReq), 0, method);
    hl = sappend(gReq, sizeof(gReq), hl, " ");
    hl = sappend(gReq, sizeof(gReq), hl, path);
    hl = sappend(gReq, sizeof(gReq), hl, " HTTP/1.1\r\nHost: " TEAMS_API_HOST "\r\n");
    hl = sappend(gReq, sizeof(gReq), hl,
                "User-Agent: " TEAMS_UA "\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n");
    if (extraHeaders) hl = sappend(gReq, sizeof(gReq), hl, extraHeaders);
    hl = sappend(gReq, sizeof(gReq), hl, "\r\n");
    if (hl >= sizeof(gReq) - 1) return -1;
    if (tls_send(&gApiTls, gReq, hl) != 0) return -1;

    // Status line: "HTTP/1.x NNN ...".
    if (read_line(&gApiTls, line, sizeof(line), deadline) != 0) return -1;
    if (!startswith(line, "HTTP/1.")) return -1;
    {
        const char* p = line + 7;
        while (*p == '.') p++;           // start of minor version
        while (*p >= '0' && *p <= '9') p++; // minor version digits
        while (*p == ' ') p++;
        while (*p >= '0' && *p <= '9') status = status * 10 + (*p++ - '0');
    }
    if (status != 200) {
        DBG_ERR("msteams: %s %s -> HTTP %d\n", method, path, status);
        return -1;
    }

    // Headers until the empty line.
    headers[0] = 0;
    for (;;) {
        unsigned long l, hl;
        if (read_line(&gApiTls, line, sizeof(line), deadline) != 0) return -1;
        if (line[0] == 0) break;
        l = bof_strlen(line);
        hl = bof_strlen(headers);
        if (hl + l + 3 > sizeof(headers)) return -1;
        bof_memcpy(headers + hl, line, l);
        headers[hl + l] = '\r';
        headers[hl + l + 1] = '\n';
        headers[hl + l + 2] = 0;
    }

    if (header_value(headers, "Transfer-Encoding", val, sizeof(val)) && startswith(val, "chunked")) {
        if (read_body_chunked(&gApiTls, out, cap, outLen, deadline) != 0) return -1;
    } else if (header_value(headers, "Content-Length", val, sizeof(val))) {
        unsigned long len = 0, i;
        for (i = 0; val[i] >= '0' && val[i] <= '9'; i++) len = len * 10 + (unsigned long)(val[i] - '0');
        if (read_body_exact(&gApiTls, out, cap, len, outLen, deadline) != 0) return -1;
    } else {
        if (read_body_until_eof(&gApiTls, out, cap, outLen, deadline) != 0) return -1;
    }
    return 0;
}

// ------------------------------------------------------------------- json

// Finds "key" in the body and returns a pointer just past the ':' (NULL if
// absent).
static const char* json_find(const char* body, unsigned long len, const char* key) {
    unsigned long ki = 0, i = 0;
    unsigned long klen = bof_strlen(key);

    while (i < len) {
        if (body[i] == '"') {
            unsigned long j = i + 1;
            while (j < len && body[j] != '"') j++;
            if (j < len && j - i - 1 == klen) {
                for (ki = 0; ki < klen; ki++) {
                    if (body[i + 1 + ki] != key[ki]) break;
                }
                if (ki == klen) {
                    // Key matched; skip whitespace to the colon, then past it.
                    unsigned long p = j + 1;
                    while (p < len && (body[p] == ' ' || body[p] == '\t' || body[p] == '\n' || body[p] == '\r')) p++;
                    if (p < len && body[p] == ':') return body + p + 1;
                }
            }
            i = j + 1;
            continue;
        }
        i++;
    }
    return NULL;
}

// Copies the JSON string at p (which must point at the opening quote).
static int json_copy_string(const char* p, char* out, unsigned long cap) {
    unsigned long n = 0;
    if (*p != '"') return -1;
    p++;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\') {
            char e = *p++;
            if (!e) return -1;
            switch (e) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'u': // keep simple: \uXXXX -> '?'
                if (p[0] && p[1] && p[2] && p[3]) p += 4;
                c = '?';
                break;
            default: c = e; break; // \" \\ \/ and anything else verbatim
            }
        }
        if (n + 1 >= cap) return -1;
        out[n++] = c;
    }
    if (*p != '"') return -1;
    out[n] = 0;
    return 0;
}

static int json_number(const char* p, unsigned long long* out) {
    unsigned long long v = 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (unsigned long long)(*p++ - '0');
    }
    *out = v;
    return 0;
}

// ------------------------------------------------------------------- fetch

int msteams_fetch(TEAMS_CREDS* out) {
    unsigned long len = 0;
    const char* p;

    bof_memset(out, 0, sizeof(*out));

    // 1. Anonymous visitor token.
    if (http_roundtrip("POST", "/api/authsvc/v1.0/authz/visitor",
                       "Authorization: Bearer\r\n"
                       "Ms-Teams-Auth-Type: ExplicitLogin\r\n"
                       "Content-Type: application/json\r\n"
                       "Accept: application/json, text/plain, */*\r\n"
                       "Content-Length: 0\r\n",
                       gHttpBuf, sizeof(gHttpBuf), &len, GetTickCount64() + 15000) != 0) {
        DBG_ERR("msteams: visitor token request failed\n");
        api_close();
        return -1;
    }
    api_close();

    gHttpBuf[len < sizeof(gHttpBuf) ? len : sizeof(gHttpBuf) - 1] = 0;
    p = json_find((const char*)gHttpBuf, len, "skypeToken");
    if (!p || json_copy_string(p, gToken, sizeof(gToken)) != 0) {
        DBG_ERR("msteams: skypeToken not found in visitor response\n");
        return -1;
    }

    // 2. TURN credentials.
    {
        char hdr[1200];
        unsigned long hl = sappend(hdr, sizeof(hdr), 0, "X-Skypetoken: ");
        hl = sappend(hdr, sizeof(hdr), hl, gToken);
        hl = sappend(hdr, sizeof(hdr), hl,
                     "\r\nAccept: application/json, text/javascript\r\n");
        if (hl >= sizeof(hdr) - 1) return -1;

        if (http_roundtrip("GET", "/trap-exp/tokens", hdr,
                          gHttpBuf, sizeof(gHttpBuf), &len, GetTickCount64() + 15000) != 0) {
            DBG_ERR("msteams: tokens request failed\n");
            api_close();
            return -1;
        }
        api_close();
    }

    gHttpBuf[len < sizeof(gHttpBuf) ? len : sizeof(gHttpBuf) - 1] = 0;
    p = json_find((const char*)gHttpBuf, len, "username");
    if (!p || json_copy_string(p, out->username, sizeof(out->username)) != 0) {
        DBG_ERR("msteams: username not found in tokens response\n");
        return -1;
    }
    p = json_find((const char*)gHttpBuf, len, "password");
    if (!p || json_copy_string(p, out->password, sizeof(out->password)) != 0) {
        DBG_ERR("msteams: password not found in tokens response\n");
        return -1;
    }

    // The "expires" field's unit is undocumented; mirror the Go
    // interpretation heuristics.
    p = json_find((const char*)gHttpBuf, len, "expires");
    if (p) {
        unsigned long long v = 0;
        if (json_number(p, &v) == 0) {
            if (v > 1000000000000ULL) out->expiresUnix = v / 1000; // ms since epoch
            else if (v > 1000000000ULL) out->expiresUnix = v;     // s since epoch
            else if (v > 0) out->expiresUnix = msteams_now_unix() + v; // validity seconds
        }
    }

#ifdef TURN_DEBUG
    {
        char head[17];
        unsigned long i;
        for (i = 0; i < 16 && out->username[i]; i++) head[i] = out->username[i];
        head[i] = 0;
        DBG("msteams: fetched credentials (username %s..., expires in %llu s)\n",
            head, out->expiresUnix ? out->expiresUnix - msteams_now_unix() : 0ULL);
    }
#endif
    return 0;
}
