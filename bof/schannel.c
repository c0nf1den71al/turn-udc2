// schannel.c — see schannel.h
#include "schannel.h"
#include "crypto.h"
#include "bof_config.h"

#ifdef TURN_DEBUG
#include <stdio.h>
#endif

#define ISC_REQ_BOF                                                             \
    (ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY |    \
     ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM)

#define WSAETIMEDOUT_LIKE 10060

static int sock_send_all(SOCKET s, const char* buf, unsigned long len) {
    unsigned long sent = 0;
    while (sent < len) {
        int n = send(s, buf + sent, (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (unsigned long)n;
    }
    return 0;
}

// Receives more ciphertext into t->inBuf, retrying while the socket
// times out but the deadline has not passed. Returns 1 when data was
// received, 0 on deadline, -1 on error/closed.
static int sock_recv_more(TLS_CTX* t, unsigned long long deadline) {
    int n;
    if (t->inLen >= sizeof(t->inBuf)) return -1;
    for (;;) {
        if (GetTickCount64() >= deadline) return 0;
        n = recv(t->sock, (char*)t->inBuf + t->inLen, (int)(sizeof(t->inBuf) - t->inLen), 0);
        if (n > 0) {
            t->inLen += (unsigned long)n;
#ifdef TURN_DEBUG
            if (t->inLen == (unsigned long)n) {
                fprintf(stderr, "[*] tls: received %d bytes (first after idle)\n", n);
            }
#endif
            return 1;
        }
        if (n == 0) {
#ifdef TURN_DEBUG
            fprintf(stderr, "[-] tls: server closed connection (recv=0)\n");
#endif
            return -1; // orderly shutdown
        }
        if (WSAGetLastError() == WSAETIMEDOUT_LIKE) continue;
#ifdef TURN_DEBUG
        fprintf(stderr, "[-] tls: recv error %d\n", WSAGetLastError());
#endif
        return -1;
    }
}

int tls_connect(TLS_CTX* t, SOCKET sock, const char* serverName, unsigned long long deadline) {
    SCHANNEL_CRED cred;
    SECURITY_STATUS ret;
    SecBuffer outBuffer;
    SecBufferDesc outDesc;
    SecBuffer inBuffer;
    SecBufferDesc inDesc;
    unsigned long contextAttr = 0;
    TimeStamp expiry;
    BOOL haveInput = FALSE;
    int rounds = 0;

    bof_memset(t, 0, sizeof(*t));
    t->sock = sock;

    bof_memset(&cred, 0, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    // Automatic certificate validation (chain + name) like a browser; no
    // revocation check for reliability. No client certificate is sent.
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_AUTO_CRED_VALIDATION;

    ret = AcquireCredentialsHandleA(NULL, (SEC_CHAR*)UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
                                   NULL, &cred, NULL, NULL, &t->hCred, &expiry);
    if (ret != SEC_E_OK) return -1;
    t->haveCred = TRUE;

    for (;;) {
        outBuffer.BufferType = SECBUFFER_TOKEN;
        outBuffer.cbBuffer = 0;
        outBuffer.pvBuffer = NULL;
        outDesc.ulVersion = SECBUFFER_VERSION;
        outDesc.cBuffers = 1;
        outDesc.pBuffers = &outBuffer;

        ret = InitializeSecurityContextA(&t->hCred,
                                        t->haveCtx ? &t->hCtx : NULL,
                                        (SEC_CHAR*)serverName,
                                        ISC_REQ_BOF,
                                        0,
                                        SECURITY_NATIVE_DREP,
                                        haveInput ? &inDesc : NULL,
                                        0,
                                        &t->hCtx,
                                        &outDesc,
                                        &contextAttr,
                                        &expiry);
        t->haveCtx = TRUE;

        if (outBuffer.cbBuffer > 0 && outBuffer.pvBuffer != NULL) {
            if (sock_send_all(t->sock, (const char*)outBuffer.pvBuffer, outBuffer.cbBuffer) != 0) {
                FreeContextBuffer(outBuffer.pvBuffer);
                return -1;
            }
            FreeContextBuffer(outBuffer.pvBuffer);
        }

        if (ret == SEC_E_OK) {
            // Handshake complete; any bytes still staged would be early
            // application records, which cannot precede our Finished.
            t->inLen = 0;
            break;
        }

        if (ret == SEC_I_CONTINUE_NEEDED) {
            // The offered input was fully consumed; fetch the next flight.
            t->inLen = 0;
            if (sock_recv_more(t, deadline) != 1) return -1;
        } else if (ret == SEC_E_INCOMPLETE_MESSAGE) {
            // Keep what we have and pull more bytes for this flight.
            if (sock_recv_more(t, deadline) != 1) return -1;
        } else {
            // Any other status (untrusted root, expired certificate, ...)
            // is fatal.
            return -1;
        }

        inBuffer.BufferType = SECBUFFER_TOKEN;
        inBuffer.cbBuffer = (unsigned long)t->inLen;
        inBuffer.pvBuffer = t->inBuf;
        inDesc.ulVersion = SECBUFFER_VERSION;
        inDesc.cBuffers = 1;
        inDesc.pBuffers = &inBuffer;
        haveInput = TRUE;

        if (++rounds > 64) return -1;
    }

    if (QueryContextAttributesA(&t->hCtx, SECPKG_ATTR_STREAM_SIZES, &t->sizes) != SEC_E_OK) {
        return -1;
    }
    if (t->sizes.cbHeader > 128 || t->sizes.cbTrailer > 128) return -1;
    return 0;
}

static int tls_decrypt_record(TLS_CTX* t, unsigned long long deadline) {
    SecBuffer buffers[4];
    SecBufferDesc desc;
    SECURITY_STATUS ret;
    unsigned char* data;
    unsigned long dataLen;
    unsigned char* extra;
    unsigned long extraLen;
    int i;
    int got;

    for (;;) {
        if (t->inLen == 0) {
            got = sock_recv_more(t, deadline);
            if (got < 0) return -1;
            if (got == 0) return 0; // deadline, no record yet
        }

        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[0].cbBuffer = (unsigned long)t->inLen;
        buffers[0].pvBuffer = t->inBuf;
        for (i = 1; i < 4; i++) {
            buffers[i].BufferType = SECBUFFER_EMPTY;
            buffers[i].cbBuffer = 0;
            buffers[i].pvBuffer = NULL;
        }
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buffers;

        ret = DecryptMessage(&t->hCtx, &desc, 0, NULL);

#ifdef TURN_DEBUG
        if (ret != SEC_E_OK) {
            fprintf(stderr, "[*] tls_decrypt: DecryptMessage returned 0x%lx (inLen=%lu)\n",
                    (unsigned long)ret, (unsigned long)t->inLen);
        }
#endif

        if (ret == SEC_E_INCOMPLETE_MESSAGE) {
            got = sock_recv_more(t, deadline);
            if (got < 0) return -1;
            if (got == 0) return 0; // deadline
            continue;
        }
        if (ret == SEC_I_CONTEXT_EXPIRED) return -1;
        if (ret != SEC_E_OK) return -1;

        data = NULL;
        dataLen = 0;
        extra = NULL;
        extraLen = 0;
        for (i = 0; i < 4; i++) {
            if (buffers[i].BufferType == SECBUFFER_DATA && !data) {
                data = (unsigned char*)buffers[i].pvBuffer;
                dataLen = buffers[i].cbBuffer;
            } else if (buffers[i].BufferType == SECBUFFER_EXTRA) {
                extra = (unsigned char*)buffers[i].pvBuffer;
                extraLen = buffers[i].cbBuffer;
            }
        }
        if (!data) {
#ifdef TURN_DEBUG
            fprintf(stderr, "[-] tls_decrypt: no DATA buffer in result\n");
#endif
            return -1;
        }

#ifdef TURN_DEBUG
        fprintf(stderr, "[*] tls_decrypt: got %lu bytes plaintext (extra=%lu)\n",
                (unsigned long)dataLen, (unsigned long)extraLen);
#endif

        if (t->plainLen + dataLen > sizeof(t->plain)) return -1;
        if (dataLen) {
            bof_memcpy(t->plain + t->plainLen, data, dataLen);
            t->plainLen += dataLen;
        }

        if (extraLen) {
            bof_memmove(t->inBuf, extra, extraLen);
            t->inLen = extraLen;
        } else {
            t->inLen = 0;
        }
        return 1;
    }
}

int tls_send(TLS_CTX* t, const void* data, unsigned long len) {
    // EncryptMessage encrypts the data buffer in place, so send through a
    // scratch copy. Static storage keeps the BOF allocation-free; the
    // largest message we send is one chunk plus STUN overhead.
    static unsigned char header[128];
    static unsigned char trailer[128];
    static unsigned char scratch[TURN_CHUNK_SIZE + 512];
    SecBuffer buffers[4];
    SecBufferDesc desc;
    SECURITY_STATUS ret;

    if (len == 0 || len > sizeof(scratch)) return -1;
    bof_memcpy(scratch, data, len);

    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    buffers[0].cbBuffer = t->sizes.cbHeader;
    buffers[0].pvBuffer = header;
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].cbBuffer = (unsigned long)len;
    buffers[1].pvBuffer = scratch;
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    buffers[2].cbBuffer = t->sizes.cbTrailer;
    buffers[2].pvBuffer = trailer;
    buffers[3].BufferType = SECBUFFER_EMPTY;
    buffers[3].cbBuffer = 0;
    buffers[3].pvBuffer = NULL;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = buffers;

    ret = EncryptMessage(&t->hCtx, 0, &desc, 0);
    if (ret != SEC_E_OK) {
#ifdef TURN_DEBUG
        fprintf(stderr, "[-] tls_send: EncryptMessage failed 0x%lx\n", (unsigned long)ret);
#endif
        return -1;
    }

#ifdef TURN_DEBUG
    fprintf(stderr, "[*] tls_send: sending %lu bytes (hdr=%lu data=%lu trailer=%lu)\n",
            (unsigned long)len, (unsigned long)buffers[0].cbBuffer,
            (unsigned long)buffers[1].cbBuffer, (unsigned long)buffers[2].cbBuffer);
#endif
    if (sock_send_all(t->sock, (const char*)header, buffers[0].cbBuffer) != 0) {
#ifdef TURN_DEBUG
        fprintf(stderr, "[-] tls_send: send header failed\n");
#endif
        return -1;
    }
    if (sock_send_all(t->sock, (const char*)scratch, buffers[1].cbBuffer) != 0) {
#ifdef TURN_DEBUG
        fprintf(stderr, "[-] tls_send: send data failed\n");
#endif
        return -1;
    }
    if (sock_send_all(t->sock, (const char*)trailer, buffers[2].cbBuffer) != 0) {
#ifdef TURN_DEBUG
        fprintf(stderr, "[-] tls_send: send trailer failed\n");
#endif
        return -1;
    }
#ifdef TURN_DEBUG
    fprintf(stderr, "[*] tls_send: sent OK\n");
#endif
    return 0;
}

int tls_read_exact(TLS_CTX* t, void* out, unsigned long len, unsigned long long deadline) {
    unsigned char* dst = (unsigned char*)out;
    unsigned long done = 0;
    int r;

    while (done < len) {
        unsigned long n;

        while (t->plainLen == 0) {
            if (GetTickCount64() >= deadline) return -1;
            r = tls_decrypt_record(t, deadline);
            if (r < 0) return -1;
            if (r == 0) continue; // deadline not hit yet, keep waiting
        }

        n = t->plainLen;
        if (n > len - done) n = len - done;
        bof_memcpy(dst + done, t->plain, n);
        done += n;
        t->plainLen -= n;
        if (t->plainLen) {
            bof_memmove(t->plain, t->plain + n, t->plainLen);
        }
    }
    return 0;
}

void tls_close(TLS_CTX* t) {
    if (t->haveCtx) DeleteSecurityContext(&t->hCtx);
    if (t->haveCred) FreeCredentialsHandle(&t->hCred);
    t->haveCtx = FALSE;
    t->haveCred = FALSE;
}
