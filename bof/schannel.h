// schannel.h — a minimal TLS 1.2/1.3 client over SSPI/Schannel for a
// connected socket, with no CRT dependencies.
#ifndef BOF_SCHANNEL_H
#define BOF_SCHANNEL_H

#include "dfr.h"

typedef struct _TLS_CTX {
    SOCKET sock;
    CredHandle hCred;
    BOOL haveCred;
    CtxtHandle hCtx;
    BOOL haveCtx;
    SecPkgContext_StreamSizes sizes;

    // ciphertext staging (one TLS record at a time)
    unsigned char inBuf[32768];
    unsigned long inLen;

    // decrypted plaintext not yet consumed
    unsigned char plain[32768];
    unsigned long plainLen;
} TLS_CTX;

// Performs the TLS handshake against the already-connected socket, using
// serverName as the SNI / certificate name. The socket must have receive
// timeouts configured by the caller; the handshake fails after deadline
// (GetTickCount64 milliseconds).
int tls_connect(TLS_CTX* t, SOCKET sock, const char* serverName, unsigned long long deadline);

// Sends exactly len bytes of application data.
int tls_send(TLS_CTX* t, const void* data, unsigned long len);

// Reads exactly len bytes of application data; fails after deadline
// (GetTickCount64 milliseconds).
int tls_read_exact(TLS_CTX* t, void* out, unsigned long len, unsigned long long deadline);

// Best-effort cleanup.
void tls_close(TLS_CTX* t);

#endif
