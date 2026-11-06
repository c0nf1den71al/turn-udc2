// udc2.h — Cobalt Strike User-Defined C2 (UDC2) contract.
//
// Beacon calls the BOF entry point (go) with a pointer to a UDC2_INFO
// structure. The BOF fills in its proxy and close functions. Mirrors the
// official udc2-vs template (https://github.com/Cobalt-Strike/udc2-vs).
#ifndef UDC2_H
#define UDC2_H

typedef int (*UDC2ProxyCall)(const char* sendBuf, int sendBufLen, char* recvBuf, int recvBufMaxLen);
typedef void (*UDC2ProxyClose)(void);

typedef struct _UDC2_INFO {
    DWORD version;
    UDC2ProxyCall proxyCall;
    UDC2ProxyClose proxyClose;
} UDC2_INFO, *PUDC2_INFO;

#define UDC2_VERSION 0x041200

#endif
