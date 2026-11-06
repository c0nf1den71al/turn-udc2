// stun.h — minimal STUN/TURN (RFC 5389/5766) message codec for the BOF.
#ifndef BOF_STUN_H
#define BOF_STUN_H

#include "dfr.h"

#define STUN_HEADER_SIZE 20
#define STUN_MAGIC_COOKIE 0x2112A442UL

// STUN message types (method | class).
#define STUN_ALLOCATE_REQ 0x0003
#define STUN_ALLOCATE_OK 0x0103
#define STUN_ALLOCATE_ERR 0x0113
#define STUN_REFRESH_REQ 0x0004
#define STUN_REFRESH_OK 0x0104
#define STUN_REFRESH_ERR 0x0114
#define STUN_SEND_IND 0x0016
#define STUN_DATA_IND 0x0017
#define STUN_PERMISSION_REQ 0x0008
#define STUN_PERMISSION_OK 0x0108
#define STUN_PERMISSION_ERR 0x0118

// STUN attribute types.
#define STUN_ATTR_USERNAME 0x0006
#define STUN_ATTR_MESSAGE_INTEGRITY 0x0008
#define STUN_ATTR_ERROR_CODE 0x0009
#define STUN_ATTR_LIFETIME 0x000D
#define STUN_ATTR_XOR_PEER_ADDRESS 0x0012
#define STUN_ATTR_DATA 0x0013
#define STUN_ATTR_REALM 0x0014
#define STUN_ATTR_NONCE 0x0015
#define STUN_ATTR_XOR_RELAYED_ADDRESS 0x0016
#define STUN_ATTR_REQUESTED_TRANSPORT 0x0019
#define STUN_ATTR_FINGERPRINT 0x8028

// A STUN message backed by caller-provided storage.
typedef struct _STUN_MSG {
    unsigned char* buf;   // storage
    unsigned long cap;    // storage capacity
    unsigned long len;    // current message length (header + attrs)
} STUN_MSG;

// Starts a new message with a fresh random transaction id.
void stun_start(STUN_MSG* m, unsigned short type, unsigned char* buf, unsigned long cap);

// Appends an attribute (value padded to a 4-byte boundary). Returns 0 on
// success, -1 when out of capacity.
int stun_attr(STUN_MSG* m, unsigned short type, const void* value, unsigned short valueLen);

// Appends MESSAGE-INTEGRITY (HMAC-SHA1 with the long-term key). The key
// is MD5(username ":" realm ":" password).
int stun_add_message_integrity(STUN_MSG* m, const unsigned char* key, unsigned long keyLen);

// Appends FINGERPRINT.
int stun_add_fingerprint(STUN_MSG* m);

// Finds the first attribute of the given type. Returns NULL when absent.
const unsigned char* stun_find(const STUN_MSG* m, unsigned short type, unsigned short* valueLen);

// XOR-encoded address helpers (IPv4). Raw bytes on the wire:
//   [reserved=0][family=0x01][xport:2][xaddr:4] with port^0x2112 and addr^cookie.
void stun_write_xor_address(unsigned char out[8], unsigned long ip, unsigned short port);
int stun_read_xor_address(const unsigned char v[8], unsigned long* ip, unsigned short* port);

// Parses an ERROR-CODE attribute value ([2 reserved][class][number]).
int stun_error_code(const STUN_MSG* m, int* code);

#endif
