#ifndef _NETUTILS_H
#define _NETUTILS_H

#include "winsock.h"

#define MAX_HOSTNAME_LEN 256 // FQCN <= 255 characters
#define MAX_PORT_STR_LEN 6   // PORT < 65536

#define SOCKET_BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size

typedef struct {
    char *host;
} ss_addr_t;

// Be compatible with older libc.
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

static const char mptcp_enabled_values[] = { 42, 26, 0 };

#ifndef UPDATE_INTERVAL
#define UPDATE_INTERVAL 5
#endif

/** byte size of ip4 address */
#define INET_SIZE 4
/** byte size of ip6 address */
#define INET6_SIZE 16


#endif
