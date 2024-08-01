#include "remote_client.h"

ScRemoteClient::ScRemoteClient(ScSetting *st, QObject *parent):
    QObject(parent)
{
    setting = st;
    remote = new QTcpSocket();
    connect(remote, SIGNAL(disconnected()),
            this,   SLOT  (disconnected()));
    connect(remote, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(displayError(QAbstractSocket::SocketError)));
}

void ScRemoteClient::open()
{
    remote->connectToHost(QHostAddress(setting->remote_host),
                          setting->remote_port);
}

void ScRemoteClient::writeBuf()
{
    remote->connectToHost(QHostAddress(setting->remote_host),
                          setting->remote_port);
    remote->waitForConnected();
    if( remote->isOpen()==0 )
    {
        qDebug() << "WriteBuf: failed connection not opened";
        return;
    }
    remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);

    int s = remote->write(buf);
    qDebug() << "writeBuf:" << buf.length() << s;
    buf.clear();

    remote->disconnectFromHost();
    remote->waitForDisconnected();
    remote->close();
}

void ScRemoteClient::disconnected()
{
    remote->close();
    buf.clear();
    qDebug() << "ScRemoteClient: Disconnected";
}

void ScRemoteClient::displayError(
        QAbstractSocket::SocketError socketError)
{
//    if( socketError==QTcpSocket::RemoteHostClosedError )
//    {
//        return;
//    }

    qDebug() << "Network error The following error occurred"
             << remote->errorString();
    remote->close();
}
