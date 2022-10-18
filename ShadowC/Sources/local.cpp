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

ScLocal::ScLocal(ScSetting *st, QObject *parent) : QObject(parent)
{
    setting = st;
    listen_local(setting->local_port);
    qDebug("listening at port %d", setting->local_port);

    // Init connections
//    cork_dllist_init(&connections);
}

ScLocal::~ScLocal()
{

}

void ScLocal::listen_local(int port)
{
    server = new QTcpServer;
    connect(server, SIGNAL(newConnection()),
            this, SLOT(connected()));

    if(server->listen(QHostAddress::Any, port))
    {
        qDebug() << "Server created on port " << port;
    }
    else
    {
        qDebug() << "Server failed";
        qDebug() << "Error message is:" << server->errorString();
    }

//    connect(this, SIGNAL(clientConnected()),
//            this, SLOT(connected()));

    return;
}

void ScLocal::delayed_connect_cb()
{
//    server_t *server = cork_container_of(watcher, server_t,
//                                         delayed_connect_watcher);

//    server_recv_cb(revents);
}

void ScLocal::server_send_cb()
{
}

void ScLocal::connected()
{
    qDebug() << "Server: Accepted connection";
    socks5_server = new ScSocks5Server(setting, server->nextPendingConnection());
}
