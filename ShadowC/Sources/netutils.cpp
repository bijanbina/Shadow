#include <math.h>

#include "netutils.h"
#include "utils.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

extern int verbose;

static const char valid_label_bytes[] =
    "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

int
set_reuseport(int socket)
{
    int opt = 1;
    return setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
}

size_t
get_sockaddr_len(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}


int
bind_to_addr(struct sockaddr_storage *storage,
             int socket_fd)
{
    if (storage->ss_family == AF_INET) {
        return bind(socket_fd, (struct sockaddr *)storage, sizeof(struct sockaddr_in));
    } else if (storage->ss_family == AF_INET6) {
        return bind(socket_fd, (struct sockaddr *)storage, sizeof(struct sockaddr_in6));
    }
    return -1;
}

int
sockaddr_cmp(struct sockaddr_storage *addr1,
             struct sockaddr_storage *addr2, socklen_t len)
{
    struct sockaddr_in *p1_in   = (struct sockaddr_in *)addr1;
    struct sockaddr_in *p2_in   = (struct sockaddr_in *)addr2;
    struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *)addr1;
    struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *)addr2;
    if (p1_in->sin_family < p2_in->sin_family)
        return -1;
    if (p1_in->sin_family > p2_in->sin_family)
        return 1;
    /* compare ip4 */
    if (p1_in->sin_family == AF_INET) {
        /* just order it, ntohs not required */
        if (p1_in->sin_port < p2_in->sin_port)
            return -1;
        if (p1_in->sin_port > p2_in->sin_port)
            return 1;
        return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
    } else if (p1_in6->sin6_family == AF_INET6) {
        /* just order it, ntohs not required */
        if (p1_in6->sin6_port < p2_in6->sin6_port)
            return -1;
        if (p1_in6->sin6_port > p2_in6->sin6_port)
            return 1;
        return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr,
                      INET6_SIZE);
    } else {
        /* eek unknown type, perform this comparison for sanity. */
        return memcmp(addr1, addr2, len);
    }
}

int
sockaddr_cmp_addr(struct sockaddr_storage *addr1,
                  struct sockaddr_storage *addr2, socklen_t len)
{
    struct sockaddr_in *p1_in   = (struct sockaddr_in *)addr1;
    struct sockaddr_in *p2_in   = (struct sockaddr_in *)addr2;
    struct sockaddr_in6 *p1_in6 = (struct sockaddr_in6 *)addr1;
    struct sockaddr_in6 *p2_in6 = (struct sockaddr_in6 *)addr2;
    if (p1_in->sin_family < p2_in->sin_family)
        return -1;
    if (p1_in->sin_family > p2_in->sin_family)
        return 1;
    if (verbose) {
        LOGI("sockaddr_cmp_addr: sin_family equal? %d", p1_in->sin_family == p2_in->sin_family);
    }
    /* compare ip4 */
    if (p1_in->sin_family == AF_INET) {
        return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
    } else if (p1_in6->sin6_family == AF_INET6) {
        return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr,
                      INET6_SIZE);
    } else {
        /* eek unknown type, perform this comparison for sanity. */
        return memcmp(addr1, addr2, len);
    }
}

int
validate_hostname(const char *hostname, const int hostname_len)
{
    if (hostname == NULL)
        return 0;

    if (hostname_len < 1 || hostname_len > 255)
        return 0;

    if (hostname[0] == '.')
        return 0;

    const char *label = hostname;
    while (label < hostname + hostname_len) {
        size_t label_len = hostname_len - (label - hostname);
        char *next_dot   = strchr(label, '.');
        if (next_dot != NULL)
            label_len = next_dot - label;

        if (label + label_len > hostname + hostname_len)
            return 0;

        if (label_len > 63 || label_len < 1)
            return 0;

        if (label[0] == '-' || label[label_len - 1] == '-')
            return 0;

        if (strspn(label, valid_label_bytes) < label_len)
            return 0;

        label += label_len + 1;
    }

    return 1;
}
