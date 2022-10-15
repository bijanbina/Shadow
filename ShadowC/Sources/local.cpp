#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>

#include "local.h"

#define MAX_CONNECT_TIMEOUT 10
#define MAX_REMOTE_NUM 10

int verbose    = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

static int mode      = 0;
static int ipv6first = 0;
int fast_open        = 0;
static int no_delay  = 0;
static int udp_fd    = 0;
static int ret_val   = 0;


static void free_remote(remote_t *remote);
static void free_server(server_t *server);

static remote_t *new_remote(int fd, int timeout);

void ScLocal::listen_local(int port)
{
    server = new QTcpServer;
    connect(server, SIGNAL(newConnection()),
            this, SLOT(accept_cb()));

    if(server->listen(QHostAddress::Any, port))
    {
        qDebug() << "Server created on port " << port;
    }
    else
    {
        qDebug() << "Server failed";
        qDebug() << "Error message is:" << server->errorString();
    }

    connect(this, SIGNAL(clientConnected()),
            this, SLOT(new_server()));

    return;
}

void ScLocal::delayed_connect_cb(int revents)
{
//    server_t *server = cork_container_of(watcher, server_t,
//                                         delayed_connect_watcher);

//    server_recv_cb(revents);
}


void ScLocal::server_send_cb(int revents)
{
    server_ctx_t *server_send_ctx = NULL;//(server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0)
    {
        // close and free

        return;
    }
    else
    {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                ERROR("server_send_cb_send");
            }
            return;
        }
        else if (s < (ssize_t)(server->buf->len))
        {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        }
        else
        {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
//            ev_io_stop(EV_A_ & server_send_ctx->io);
//            ev_io_start(EV_A_ & remote->recv_ctx->io);
            return;
        }
    }
}

void ScLocal::remote_timeout_cb(int revents)
{
    remote_ctx_t *remote_ctx = NULL;// cork_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    if (verbose)
    {
        LOGI("TCP connection timeout");
    }
}

void ScLocal::remote_recv_cb(int revents)
{
    remote_ctx_t *remote_recv_ctx = NULL;//(remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0)
    {
        // connection closed
        return;
    }
    else if (r == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data
            // continue to wait for recv
            return;
        }
        else
        {
            ERROR("remote_recv_cb_recv");

            return;
        }
    }

    server->buf->len = r;

    if (!remote->direct)
    {
        int err = d_ctx->stream_decrypt(server->buf);
        if (err == CRYPTO_ERROR)
        {
            LOGE("invalid password or cipher");
            return;
        }
        else if (err == CRYPTO_NEED_MORE)
        {
            return; // Wait for more
        }
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data, wait for send
            server->buf->idx = 0;
        }
        else
        {
            ERROR("remote_recv_cb_send");

            return;
        }
    }
    else if (s < (int)(server->buf->len))
    {
        server->buf->len -= s;
        server->buf->idx  = s;
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay)
    {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

void ScLocal::remote_send_cb(int revents)
{
    remote_ctx_t *remote_send_ctx = NULL;//(remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    if (!remote_send_ctx->connected)
    {
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r         = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        if (r == 0)
        {
            remote_send_ctx->connected = 1;
//            ev_timer_stop(EV_A_ & remote_send_ctx->watcher);
//            ev_io_start(EV_A_ & remote->recv_ctx->io);

            // no need to send any data
            if (remote->buf->len == 0)
            {
//                ev_io_stop(EV_A_ & remote_send_ctx->io);
//                ev_io_start(EV_A_ & server->recv_ctx->io);
                return;
            }
        }
        else
        {
            // not connected
            ERROR("getpeername");
            return;
        }
    }

    if (remote->buf->len == 0)
    {
        // close and free
        return;
    }
    else
    {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                ERROR("remote_send_cb_send");
                // close and free
            }
            return;
        }
        else if (s < (ssize_t)(remote->buf->len))
        {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        }
        else
        {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
//            ev_io_stop(EV_A_ & remote_send_ctx->io);
//            ev_io_start(EV_A_ & server->recv_ctx->io);
        }
    }
}

static remote_t * new_remote(int fd, int timeout)
{
    remote_t *remote;
    remote = (remote_t *)malloc(sizeof(remote_t));

    memset(remote, 0, sizeof(remote_t));

    remote->buf      = (buffer_t *)malloc(sizeof(buffer_t));
    remote->recv_ctx = (remote_ctx_t *)malloc(sizeof(remote_ctx_t));
    remote->send_ctx = (remote_ctx_t *)malloc(sizeof(remote_ctx_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->recv_ctx->connected = 0;
    remote->send_ctx->connected = 0;
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

//    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd);
//    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd);
//    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
//                  min(MAX_CONNECT_TIMEOUT, timeout), 0);

    return remote;
}

static void free_remote(remote_t *remote)
{
    if (remote->server != NULL)
    {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL)
    {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
free_server(server_t *server)
{
    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        crypto->stream_ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        crypto->stream_ctx_release(server->d_ctx);
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

void ScLocal::accept_cb(int revents)
{
    qDebug() << "Server: Accepted connection";
    socks5_server = new ScSocks5Server(setting, server->nextPendingConnection());

    emit clientConnected();

//    setnonblocking(serverfd);
//    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
//    server->listener = listener;
}

ScLocal::ScLocal(ScSetting *st, QObject *parent) : QObject(parent)
{
    setting = st;
    srand(time(NULL));
    USE_TTY();

    winsock_init();
    // Setup keys
    qDebug() << "initializing ciphers" << setting->method;
    crypto = new ScStream(setting->password);
    if (crypto == NULL)
    {
        FATAL("failed to initialize ciphers");
    }

//    listen_ctx.timeout = 100;
//    listen_ctx.iface   = iface;
//    listen_ctx.mptcp   = mptcp;

    LOGI("listening at port %d", setting->local_port);

    listen_local(setting->local_port);

//    setnonblocking(listenfd);

    // Init connections
//    cork_dllist_init(&connections);

    winsock_cleanup();
}
