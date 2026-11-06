// main.c — the turn_udc2 BOF test harness.
//
// Runs the exact BOF object code that Cobalt Strike patches into payloads
// (same .o files), outside Beacon: it initializes the BOF, performs one
// udc2Proxy exchange with a test frame and verifies the echo.
//
// Point it at a running turn-udc2-server backed by turn-udc2-fakets (the
// echo team server) to validate the BOF end-to-end before touching
// Cobalt Strike:
//
//   make -C bof debug
//   ./turn_udc2_test.exe            (on a Windows x64 box)
//
// The BOF must have been built from the bof_config.h emitted by the
// currently-running turn-udc2-server (same as for a real payload).
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../udc2.h"

// BOF entry point (from turn_udc2_bof.c).
void go(char* args, int len);

int loader_init(void);

int main(int argc, char** argv) {
    UDC2_INFO info;
    unsigned char* frame;
    unsigned char* recvBuf;
    unsigned int frameSize = 8192;
    int i, r;
    unsigned long long t0;

    if (argc > 1) {
        frameSize = (unsigned int)strtoul(argv[1], NULL, 10);
        if (frameSize == 0 || frameSize > 1024 * 1024) {
            fprintf(stderr, "usage: %s [frame-size 1..1048576]\n", argv[0]);
            return 2;
        }
    }

    if (!loader_init()) {
        return 1;
    }

    memset(&info, 0, sizeof(info));
    go((char*)&info, sizeof(info));
    if (!info.proxyCall || !info.proxyClose) {
        fprintf(stderr, "[-] BOF failed to register its proxy functions\n");
        return 1;
    }
    printf("[+] BOF initialized (version 0x%x)\n", info.version);

    frame = (unsigned char*)malloc(4 + frameSize);
    recvBuf = (unsigned char*)malloc(4 + frameSize);
    if (!frame || !recvBuf) {
        fprintf(stderr, "[-] out of memory\n");
        return 1;
    }
    // A Beacon frame: 4-byte little-endian length + payload.
    frame[0] = (unsigned char)(frameSize);
    frame[1] = (unsigned char)(frameSize >> 8);
    frame[2] = (unsigned char)(frameSize >> 16);
    frame[3] = (unsigned char)(frameSize >> 24);
    for (i = 4; i < (int)(4 + frameSize); i++) {
        frame[i] = (unsigned char)(i * 7);
    }

    printf("[*] sending %u-byte frame through the TURN UDC2 channel...\n", frameSize);
    t0 = GetTickCount64();
    r = info.proxyCall((const char*)frame, (int)(4 + frameSize),
                       (char*)recvBuf, (int)(4 + frameSize));
    if (r < 0) {
        fprintf(stderr, "[-] proxy call failed (r=%d); check turn-udc2-server logs\n", r);
        info.proxyClose();
        return 1;
    }
    printf("[+] proxy returned %d bytes in %llums\n", r, GetTickCount64() - t0);

    if (r != (int)(4 + frameSize) || memcmp(frame, recvBuf, r) != 0) {
        fprintf(stderr, "[-] echo mismatch (got %d bytes, expected %d)\n", r, (int)(4 + frameSize));
        info.proxyClose();
        return 1;
    }
    printf("[+] round trip OK: BOF ↔ Teams TURN ↔ turn-udc2-server ↔ fake team server\n");

    info.proxyClose();
    printf("[*] done\n");
    return 0;
}
