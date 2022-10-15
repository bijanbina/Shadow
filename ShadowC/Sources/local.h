#ifndef _LOCAL_H
#define _LOCAL_H

#include <QString>
#include <QDebug>
#include "socks5_server.h"

typedef struct listen_ctx {
    int remote_num;
    char *iface;
    int timeout;
    int fd;
    int mptcp;
    int port;
    QString address;
} listen_ctx_t;

typedef struct server_ctx {
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct server {
    int fd;
    int stage;

    ScStream *e_ctx; // encoder
    ScStream *d_ctx; // decoder
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

class ScLocal : public QObject
{
    Q_OBJECT
public:
    explicit ScLocal(ScSetting *st, QObject *parent = nullptr);
    ~ScLocal();

private slots:
    void delayed_connect_cb(int revents);
    void server_recv_cb(int revents);
    void server_send_cb(int revents);
    void remote_timeout_cb(int revents);
    void remote_recv_cb(int revents);
    void remote_send_cb(int revents);
    void accept_cb(int revents);
    void new_server(int fd);

signals:
    void errorConnection();
    void clientDisconnected();
    void clientConnected();

private:
    void listen_local(int port);

    std::vector<unsigned char> key;
    QTcpServer *server;
    ScSocks5Server *socks5_server;
    ScSetting *setting;
};

#endif // _LOCAL_H
