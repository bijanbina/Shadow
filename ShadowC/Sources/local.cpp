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

int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

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

    qDebug("TCP connection timeout");
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
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
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
