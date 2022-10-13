/*
 * local.c - Setup a socks5 proxy through remote shadowsocks server
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>


#include "netutils.h"
#include "utils.h"
#include "socks5.h"
#include "local.h"
#include "winsock.h"


#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

int verbose    = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

static crypto_t *crypto;

static int acl       = 0;
static int mode      = TCP_ONLY;
static int ipv6first = 0;
int fast_open        = 0;
static int no_delay  = 0;
static int udp_fd    = 0;
static int ret_val   = 0;

#ifndef LIB_ONLY
static struct plugin_watcher_t {
    SOCKET fd;
    uint16_t port;
    int valid;
} plugin_watcher;
#endif


static int create_and_bind(const char *addr, const char *port);
static remote_t *create_remote(listen_ctx_t *listener, struct sockaddr *addr, int direct);
static void free_remote(remote_t *remote);
static void free_server(server_t *server);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);


int
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    result            = NULL;

    s = getaddrinfo(addr, port, &hints, &result);

    if (s != 0) {
        LOGI("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        if (reuse_port) {
            int err = set_reuseport(listen_sock);
            if (err == 0) {
                LOGI("tcp port reuse enabled");
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
        listen_sock = -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static void
delayed_connect_cb(int revents)
{
//    server_t *server = cork_container_of(watcher, server_t,
//                                         delayed_connect_watcher);

    server_recv_cb(revents);
}

static int
server_handshake_reply(int udp_assc, struct socks5_response *response)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    if (server->stage != STAGE_HANDSHAKE)
        return 0;

    struct sockaddr_in sock_addr;
    if (udp_assc) {
        socklen_t addr_len = sizeof(sock_addr);
        if (getsockname(server->fd, (struct sockaddr *)&sock_addr, &addr_len) < 0) {
            LOGE("getsockname: %s", strerror(errno));
            response->rep = SOCKS5_REP_CONN_REFUSED;
            send(server->fd, (char *)response, sizeof(struct socks5_response), 0);

            return -1;
        }
    } else
        memset(&sock_addr, 0, sizeof(sock_addr));

    buffer_t resp_to_send;
    buffer_t *resp_buf = &resp_to_send;
    balloc(resp_buf, SOCKET_BUF_SIZE);

    memcpy(resp_buf->data, response, sizeof(struct socks5_response));
    memcpy(resp_buf->data + sizeof(struct socks5_response),
           &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
    memcpy(resp_buf->data + sizeof(struct socks5_response) +
           sizeof(sock_addr.sin_addr),
           &sock_addr.sin_port, sizeof(sock_addr.sin_port));

    int reply_size = sizeof(struct socks5_response) +
                     sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);

    int s = send(server->fd, resp_buf->data, reply_size, 0);

    bfree(resp_buf);

    if (s < reply_size) {
        LOGE("failed to send fake reply");

        return -1;
    }
    if (udp_assc) {
        // Wait until client closes the connection
        return -1;
    }
    return 0;
}

static int
server_handshake(buffer_t *buf)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    struct socks5_request *request = (struct socks5_request *)buf->data;
    size_t request_len             = sizeof(struct socks5_request);

    if (buf->len < request_len) {
        return -1;
    }

    struct socks5_response response;
    response.ver  = SVERSION;
    response.rep  = SOCKS5_REP_SUCCEEDED;
    response.rsv  = 0;
    response.atyp = SOCKS5_ATYP_IPV4;

    if (request->cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
        if (verbose) {
            LOGI("udp assc request accepted");
        }
        return server_handshake_reply(1, &response);
    } else if (request->cmd != SOCKS5_CMD_CONNECT) {
        LOGE("unsupported command: %d", request->cmd);
        response.rep = SOCKS5_REP_CMD_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, 4, 0);

        return -1;
    }

    char host[MAX_HOSTNAME_LEN + 1], ip[INET6_ADDRSTRLEN], port[16];

    buffer_t *abuf = server->abuf;
    abuf->idx = 0;
    abuf->len = 0;

    abuf->data[abuf->len++] = request->atyp;
    int atyp = request->atyp;

    // get remote addr and port
    if (atyp == SOCKS5_ATYP_IPV4) {
        size_t in_addr_len = sizeof(struct in_addr);
        if (buf->len < request_len + in_addr_len + 2) {
            return -1;
        }
        memcpy(abuf->data + abuf->len, buf->data + request_len, in_addr_len + 2);
        abuf->len += in_addr_len + 2;

        if (acl || verbose) {
            uint16_t p = load16_be(buf->data + request_len + in_addr_len);
            if (!inet_ntop(AF_INET, (const void *)(buf->data + request_len),
                           ip, INET_ADDRSTRLEN)) {
                LOGI("inet_ntop(AF_INET): %s", strerror(errno));
                ip[0] = '\0';
            }
            sprintf(port, "%d", p);
        }
    } else if (atyp == SOCKS5_ATYP_DOMAIN) {
        uint8_t name_len = *(uint8_t *)(buf->data + request_len);
        if (buf->len < request_len + 1 + name_len + 2) {
            return -1;
        }
        abuf->data[abuf->len++] = name_len;
        memcpy(abuf->data + abuf->len, buf->data + request_len + 1, name_len + 2);
        abuf->len += name_len + 2;

        if (acl || verbose) {
            uint16_t p = load16_be(buf->data + request_len + 1 + name_len);
            memcpy(host, buf->data + request_len + 1, name_len);
            host[name_len] = '\0';
            sprintf(port, "%d", p);
        }
    } else if (atyp == SOCKS5_ATYP_IPV6) {
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (buf->len < request_len + in6_addr_len + 2) {
            return -1;
        }
        memcpy(abuf->data + abuf->len, buf->data + request_len, in6_addr_len + 2);
        abuf->len += in6_addr_len + 2;

        if (acl || verbose) {
            uint16_t p = load16_be(buf->data + request_len + in6_addr_len);
            if (!inet_ntop(AF_INET6, (const void *)(buf->data + request_len),
                           ip, INET6_ADDRSTRLEN)) {
                LOGI("inet_ntop(AF_INET6): %s", strerror(errno));
                ip[0] = '\0';
            }
            sprintf(port, "%d", p);
        }
    } else {
        LOGE("unsupported addrtype: %d", request->atyp);
        response.rep = SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, 4, 0);

        return -1;
    }

    if (server_handshake_reply(0, &response) < 0)
        return -1;
    server->stage = STAGE_STREAM;

    buf->len -= (3 + abuf->len);
    if (buf->len > 0) {
        memmove(buf->data, buf->data + 3 + abuf->len, buf->len);
    }

    if (atyp == SOCKS5_ATYP_DOMAIN)
        LOGI("connect to %s:%s", host, port);
    else if (atyp == SOCKS5_ATYP_IPV4)
        LOGI("connect to %s:%s", ip, port);
    else if (atyp == SOCKS5_ATYP_IPV6)
        LOGI("connect to [%s]:%s", ip, port);
not_bypass:
    // Not bypass
    if (remote == NULL) {
        remote = create_remote(server->listener, NULL, 0);
    }

    if (remote == NULL) {
        LOGE("invalid remote addr");
        return -1;
    }

    if (!remote->direct) {
        int err = crypto->encrypt(abuf, server->e_ctx, SOCKET_BUF_SIZE);
        if (err) {
            LOGE("invalid password or cipher");

            return -1;
        }
    }

    if (buf->len > 0) {
        memcpy(remote->buf->data, buf->data, buf->len);
        remote->buf->len = buf->len;
    }

    server->remote = remote;
    remote->server = server;

    if (buf->len > 0)
    {
        return 0;
    }
    else
    {
//        ev_timer_start(EV_A_ & server->delayed_connect_watcher);
    }

    return -1;
}

static void
server_stream(buffer_t *buf)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    if (remote == NULL) {
        LOGE("invalid remote");
        return;
    }

    // insert shadowsocks header
    if (!remote->direct) {

        int err = crypto->encrypt(remote->buf, server->e_ctx, SOCKET_BUF_SIZE);

        if (err) {
            LOGE("invalid password or cipher");
            return;
        }

        if (server->abuf) {
            bprepend(remote->buf, server->abuf, SOCKET_BUF_SIZE);
            bfree(server->abuf);
            ss_free(server->abuf);
            server->abuf = NULL;
        }
    }

    if (!remote->send_ctx->connected) {
        remote->buf->idx = 0;

        if (fast_open==0 || remote->direct)
        {
            // connecting, wait until connected
            int r = connect(remote->fd, (struct sockaddr *)&(remote->addr), remote->addr_len);

            if (r == -1 && errno != CONNECT_IN_PROGRESS) {
                ERROR("connect");
                return;
            }

            // wait on remote connected event
//            ev_io_stop(EV_A_ & server_recv_ctx->io);
//            ev_io_start(EV_A_ & remote->send_ctx->io);
//            ev_timer_start(EV_A_ & remote->send_ctx->watcher);
        }

    }
    else {

        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf->idx = 0;
//                ev_io_stop(EV_A_ & server_recv_ctx->io);
//                ev_io_start(EV_A_ & remote->send_ctx->io);
                return;
            } else {
                ERROR("server_recv_cb_send");
                return;
            }
        } else if (s < (int)(remote->buf->len)) {
            remote->buf->len -= s;
            remote->buf->idx  = s;
//            ev_io_stop(EV_A_ & server_recv_ctx->io);
//            ev_io_start(EV_A_ & remote->send_ctx->io);
            return;
        } else {
            remote->buf->idx = 0;
            remote->buf->len = 0;
        }
    }
}

static void
server_recv_cb(int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;
    buffer_t *buf;
    ssize_t r;

//    ev_timer_stop(EV_A_ & server->delayed_connect_watcher);

    if (remote == NULL) {
        buf = server->buf;
    } else {
        buf = remote->buf;
    }

    if (revents != EV_TIMER) {
        r = recv(server->fd, buf->data + buf->len, SOCKET_BUF_SIZE - buf->len, 0);

        if (r == 0) {
            // connection closed
            return;
        } else if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data
                // continue to wait for recv
                return;
            } else {
                if (verbose)
                    ERROR("server_recv_cb_recv");
                return;
            }
        }
        buf->len += r;
    }

    while (1) {
        // local socks5 server
        if (server->stage == STAGE_STREAM) {
            server_stream(buf);

            // all processed
            return;
        } else if (server->stage == STAGE_INIT) {
            if (verbose) {
                struct sockaddr_in peer_addr;
                socklen_t peer_addr_len = sizeof peer_addr;
                if (getpeername(server->fd, (struct sockaddr *)&peer_addr, &peer_addr_len) == 0) {
                    LOGI("connection from %s:%hu", inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
                }
            }
            if (buf->len < 1)
                return;
            if (buf->data[0] != SVERSION) {
                return;
            }
            if (buf->len < sizeof(struct method_select_request)) {
                return;
            }
            struct method_select_request *method = (struct method_select_request *)buf->data;
            int method_len                       = method->nmethods + sizeof(struct method_select_request);
            if (buf->len < method_len)
            {
                return;
            }

            struct method_select_response response;
            response.ver    = SVERSION;
            response.method = METHOD_UNACCEPTABLE;
            for (int i = 0; i < method->nmethods; i++)
                if (method->methods[i] == METHOD_NOAUTH) {
                    response.method = METHOD_NOAUTH;
                    break;
                }
            char *send_buf = (char *)&response;
            send(server->fd, send_buf, sizeof(response), 0);
            if (response.method == METHOD_UNACCEPTABLE) {
                return;
            }

            server->stage = STAGE_HANDSHAKE;

            if (method_len < (int)(buf->len)) {
                memmove(buf->data, buf->data + method_len, buf->len - method_len);
                buf->len -= method_len;
                continue;
            }

            buf->len = 0;
            return;
        } else if (server->stage == STAGE_HANDSHAKE) {
            int ret = server_handshake(buf);
            if (ret)
                return;
        }
    }
}

static void
server_send_cb(int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0) {
        // close and free

        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_cb_send");

            }
            return;
        } else if (s < (ssize_t)(server->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
//            ev_io_stop(EV_A_ & server_send_ctx->io);
//            ev_io_start(EV_A_ & remote->recv_ctx->io);
            return;
        }
    }
}

static void
remote_timeout_cb(int revents)
{
    remote_ctx_t *remote_ctx = cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    if (verbose) {
        LOGI("TCP connection timeout");
    }
}

static void
remote_recv_cb(int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote_recv_cb_recv");

            return;
        }
    }

    server->buf->len = r;

    if (!remote->direct) {
        int err = crypto->decrypt(server->buf, server->d_ctx, SOCKET_BUF_SIZE);
        if (err == CRYPTO_ERROR) {
            LOGE("invalid password or cipher");
            return;
        } else if (err == CRYPTO_NEED_MORE) {
            return; // Wait for more
        }
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
        } else {
            ERROR("remote_recv_cb_send");

            return;
        }
    } else if (s < (int)(server->buf->len)) {
        server->buf->len -= s;
        server->buf->idx  = s;
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void
remote_send_cb(int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    if (!remote_send_ctx->connected) {
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r         = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0) {
            remote_send_ctx->connected = 1;
//            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
//            ev_io_start(EV_A_ & remote->recv_ctx->io);

            // no need to send any data
            if (remote->buf->len == 0) {
//                ev_io_stop(EV_A_ & remote_send_ctx->io);
//                ev_io_start(EV_A_ & server->recv_ctx->io);
                return;
            }
        } else {
            // not connected
            ERROR("getpeername");
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free

        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
                // close and free

            }
            return;
        } else if (s < (ssize_t)(remote->buf->len)) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
//            ev_io_stop(EV_A_ & remote_send_ctx->io);
//            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_t *remote;
    remote = ss_malloc(sizeof(remote_t));

    memset(remote, 0, sizeof(remote_t));

    remote->buf      = ss_malloc(sizeof(buffer_t));
    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}


static server_t *
new_server(int fd)
{
    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    server->abuf     = ss_malloc(sizeof(buffer_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    balloc(server->abuf, SOCKET_BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    server->stage               = STAGE_INIT;
    server->recv_ctx->connected = 0;
    server->send_ctx->connected = 0;
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->send_ctx->server    = server;

    server->e_ctx = ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = ss_malloc(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

//    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
//    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);

//    ev_timer_init(&server->delayed_connect_watcher,
//                  delayed_connect_cb, 0.05, 0);

//    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void
free_server(server_t *server)
{
    cork_dllist_remove(&server->entries);

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        crypto->ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        crypto->ctx_release(server->d_ctx);
        ss_free(server->d_ctx);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    if (server->abuf != NULL) {
        bfree(server->abuf);
        ss_free(server->abuf);
    }
    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static remote_t *
create_remote(listen_ctx_t *listener,
              struct sockaddr *addr,
              int direct)
{
    struct sockaddr *remote_addr;

    int index = rand() % listener->remote_num;
    if (addr == NULL) {
        remote_addr = listener->remote_addr[index];
    } else {
        remote_addr = addr;
    }

    int protocol = IPPROTO_TCP;
    if (listener->mptcp < 0) {
        protocol = IPPROTO_MPTCP; // Enable upstream MPTCP
    }
    int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, protocol);
    if (remotefd == -1) {
        ERROR("socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));


    // Enable out-of-tree MPTCP
    if (listener->mptcp > 1) {
        int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    } else if (listener->mptcp == 1) {
        int i = 0;
        while ((listener->mptcp = mptcp_enabled_values[i]) > 0) {
            int err = setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
            if (err != -1) {
                break;
            }
            i++;
        }
        if (listener->mptcp == 0) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    }

    if (tcp_outgoing_sndbuf > 0) {
        setsockopt(remotefd, SOL_SOCKET, SO_SNDBUF, &tcp_outgoing_sndbuf, sizeof(int));
    }

    if (tcp_outgoing_rcvbuf > 0) {
        setsockopt(remotefd, SOL_SOCKET, SO_RCVBUF, &tcp_outgoing_rcvbuf, sizeof(int));
    }

    // Setup
    setnonblocking(remotefd);

    remote_t *remote = new_remote(remotefd, direct ? MAX_CONNECT_TIMEOUT : listener->timeout);
    remote->addr_len = get_sockaddr_len(remote_addr);
    memcpy(&(remote->addr), remote_addr, remote->addr_len);
    remote->direct = direct;

    if (verbose) {
        struct sockaddr_in *sockaddr = (struct sockaddr_in *)&remote->addr;
        LOGI("remote: %s:%hu", inet_ntoa(sockaddr->sin_addr), ntohs(sockaddr->sin_port));
    }

    return remote;
}

static void
signal_cb(int revents)
{
    if (revents) {
        switch (w->signum) {
        case SIGINT:
        case SIGTERM:
            ;
//            ev_signal_stop(EV_DEFAULT, &sigint_watcher);
//            ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

//            ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
        }
    }
}

void
accept_cb(int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));

    if (tcp_incoming_sndbuf > 0) {
        setsockopt(serverfd, SOL_SOCKET, SO_SNDBUF, &tcp_incoming_sndbuf, sizeof(int));
    }

    if (tcp_incoming_rcvbuf > 0) {
        setsockopt(serverfd, SOL_SOCKET, SO_RCVBUF, &tcp_incoming_rcvbuf, sizeof(int));
    }

    server_t *server = new_server(serverfd);
    server->listener = listener;
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags    = 0;
    int mtu          = 0;
    int mptcp        = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password   = NULL;
    char *key        = NULL;
    char *timeout    = NULL;
    char *method     = NULL;
    char *pid_path   = NULL;
    char *conf_path  = NULL;
    char *iface      = NULL;

    char *plugin      = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    memset(remote_addr, 0, sizeof(ss_addr_t) * MAX_REMOTE_NUM);
    srand(time(NULL));

    static struct option long_options[] = {
        { "reuse-port",  no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF },
        { "tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF },
        { "tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF },
        { "tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF },
        { "fast-open",   no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "no-delay",    no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "acl",         required_argument, NULL, GETOPT_VAL_ACL         },
        { "mtu",         required_argument, NULL, GETOPT_VAL_MTU         },
        { "mptcp",       no_argument,       NULL, GETOPT_VAL_MPTCP       },
        { "plugin",      required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts", required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "password",    required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",         required_argument, NULL, GETOPT_VAL_KEY         },
        { "help",        no_argument,       NULL, GETOPT_VAL_HELP        },
        { NULL,          0,                 NULL, 0                      }
    };

    opterr = 0;

    USE_TTY();
    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:a:n:huUv6A", long_options, NULL)) != -1)
    {
        switch (c) {
        case GETOPT_VAL_KEY:
            key = optarg;
            break;
        case GETOPT_VAL_REUSE_PORT:
            reuse_port = 1;
            break;
        case 's':
            if (remote_num < MAX_REMOTE_NUM)
            {
                parse_addr(optarg, &remote_addr[remote_num++]);
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
            break;
        case GETOPT_VAL_PASSWORD:
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'b':
            local_addr = optarg;
            break;
        case 'a':
            user = optarg;
            break;
        }
    }
    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++)
                remote_addr[i] = conf->remote_addr[i];
        }
        if (remote_port == NULL) {
            remote_port = conf->remote_port;
        }
        if (local_addr == NULL) {
            local_addr = conf->local_addr;
        }
        if (local_port == NULL) {
            local_port = conf->local_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (key == NULL) {
            key = conf->key;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (reuse_port == 0) {
            reuse_port = conf->reuse_port;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
    }

#ifdef __MINGW32__
    winsock_init();
#endif

    if (tcp_incoming_sndbuf != 0 && tcp_incoming_sndbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_sndbuf = 0;
    }

    if (tcp_incoming_sndbuf != 0) {
        LOGI("set TCP incoming connection send buffer size to %d", tcp_incoming_sndbuf);
    }

    if (tcp_incoming_rcvbuf != 0 && tcp_incoming_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_rcvbuf = 0;
    }

    if (tcp_incoming_rcvbuf != 0) {
        LOGI("set TCP incoming connection receive buffer size to %d", tcp_incoming_rcvbuf);
    }

    if (tcp_outgoing_sndbuf != 0 && tcp_outgoing_sndbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_sndbuf = 0;
    }

    if (tcp_outgoing_sndbuf != 0) {
        LOGI("set TCP outgoing connection send buffer size to %d", tcp_outgoing_sndbuf);
    }

    if (tcp_outgoing_rcvbuf != 0 && tcp_outgoing_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_rcvbuf = 0;
    }

    if (tcp_outgoing_rcvbuf != 0) {
        LOGI("set TCP outgoing connection receive buffer size to %d", tcp_outgoing_rcvbuf);
    }

    // Init connections
//    cork_dllist_init(&connections);


    if (mode != UDP_ONLY)
    {
        for (i = 0; i < listen_ctx.remote_num; i++)
            ss_free(listen_ctx.remote_addr[i]);
        ss_free(listen_ctx.remote_addr);
    }

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return ret_val;
}