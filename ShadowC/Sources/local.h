#ifndef SC_LOCAL_H
#define SC_LOCAL_H

#include <QString>
#include <QDebug>
#ifdef WIN32
#include "socks5_server.h"
#endif
#include "remote_client.h"
#include "sc_apache_se.h"

#ifdef WIN32
typedef struct listen_ctx
{
    int remote_num;
    char *iface;
    int timeout;
    int fd;
    int mptcp;
    int port;
    QString address;
} listen_ctx_t;

typedef struct server_ctx
{
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct server
{
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

typedef struct remote_ctx
{
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote
{
    int fd;
    int direct;
    int addr_len;
    uint32_t counter;
    buffer_t *buf;

    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
} remote_t;
#endif

class ScLocal : public QObject
{
    Q_OBJECT
public:
    explicit ScLocal(ScSetting *st, QObject *parent = nullptr);

private slots:
    void connected();

signals:
    void errorConnection();
    void clientDisconnected();
    void clientConnected();

private:
    void listenLocal();
    void testTX();

    QTcpServer *server;
#ifdef WIN32
    ScSocks5Server *socks5_server;
#endif
    ScSetting *setting;
};

#endif // SC_LOCAL_H
