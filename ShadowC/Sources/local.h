#ifndef _LOCAL_H
#define _LOCAL_H

#include "winsock.h"
#include "crypto.h"
#include "common.h"

typedef struct listen_ctx {
    int remote_num;
    int timeout;
    int fd;
    int mptcp;
    struct sockaddr **remote_addr;
} listen_ctx_t;

typedef struct server_ctx {
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct server {
    int fd;
    int stage;

    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listener;
    struct remote *remote;

    buffer_t *buf;
    buffer_t *abuf;
} server_t;

typedef struct remote_ctx {
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
    int direct;
    int addr_len;
    uint32_t counter;
    buffer_t *buf;

    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
    struct sockaddr_storage addr;
} remote_t;

#endif // _LOCAL_H
