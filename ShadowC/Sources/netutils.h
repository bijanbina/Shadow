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

size_t get_sockaddr_len(struct sockaddr *addr);
int set_reuseport(int socket);

int bind_to_addr(struct sockaddr_storage *storage, int socket_fd);

/**
 * Compare two sockaddrs. Imposes an ordering on the addresses.
 * Compares address and port.
 * @param addr1: address 1.
 * @param addr2: address 2.
 * @param len: lengths of addr.
 * @return: 0 if addr1 == addr2. -1 if addr1 is smaller, +1 if larger.
 */
int sockaddr_cmp(struct sockaddr_storage *addr1,
                 struct sockaddr_storage *addr2, socklen_t len);

/**
 * Compare two sockaddrs. Compares address, not the port.
 * @param addr1: address 1.
 * @param addr2: address 2.
 * @param len: lengths of addr.
 * @return: 0 if addr1 == addr2. -1 if addr1 is smaller, +1 if larger.
 */
int sockaddr_cmp_addr(struct sockaddr_storage *addr1,
                      struct sockaddr_storage *addr2, socklen_t len);

int validate_hostname(const char *hostname, const int hostname_len);


#endif
