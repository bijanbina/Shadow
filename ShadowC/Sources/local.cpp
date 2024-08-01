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

ScLocal::ScLocal(ScSetting *st, QObject *parent):
    QObject(parent)
{
    setting = st;
//    listen_local();
    if( setting->is_server )
    {
        ScApacheSe *server = new ScApacheSe;
        server->bind(setting->remote_port);
    }
    else
    {
        testTX();
    }
}

void ScLocal::listenLocal()
{
    server = new QTcpServer;
    connect(server, SIGNAL(newConnection()),
            this, SLOT(connected()));

    if( server->listen(QHostAddress::Any, setting->local_port) )
    {
        qDebug() << "Server created on port "
                 << setting->local_port;
    }
    else
    {
        qDebug() << "Server failed";
        qDebug() << "Error message is:" << server->errorString();
    }
}

void ScLocal::connected()
{
    qDebug() << "Server: Accepted connection";
#ifdef WN32
    socks5_server = new ScSocks5Server(setting,
                        server->nextPendingConnection());
#endif
}

void ScLocal::testTX()
{
    ScRemoteClient client(setting);

    int len = 1000;
    for( int i=0 ; i<len ; i++ )
    {
        client.buf += "<";
        client.buf += QString::number(i);
        client.buf += ">";
    }

    client.writeBuf();
}
