#include "remote_client.h"

ScRemoteClient::ScRemoteClient(ScSetting *st, QObject *parent) : QObject(parent)
{
    connect(remote_socket, SIGNAL(connected()), this, SLOT(connected()));
    connect(remote_socket, SIGNAL(disconnected()), this, SLOT(disconnected()));
    connect(remote_socket, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(displayError(QAbstractSocket::SocketError)));
}

void ScRemoteClient::connected()
{
    qDebug() << "Client: Connected";
    remote_socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(remote_socket, SIGNAL(readyRead()), this, SLOT(readyRead()));
//    timer->stop();
}

void ScRemoteClient::readyRead()
{
   QString read_data = remote_socket->readAll();

   if( read_data.size()==0 )
   {
       return;
   }

   if( read_data.size() )
   {
       qDebug() <<  "Client: Received=" << read_data << read_data.size();
       emit newKey(read_data);
   }
}

void ScRemoteClient::disconnected()
{
//    QMetaObject::invokeMethod(root, "set_disconnected");
//    m_wakeLock.callMethod<void>("release", "()V");
    remote_socket->close();
//    disconnect((&tcpClient, SIGNAL(readyRead()), this, SLOT(readyRead())));

    if( !(timer->isActive()) )
    {
        timer->start(RE_TIMEOUT);
        qDebug() << "Client: Timer start";
    }
    qDebug() << "Client: Disconnected";
}

void ScRemoteClient::displayError(QAbstractSocket::SocketError socketError)
{
    if( socketError==QTcpSocket::RemoteHostClosedError )
    {
        return;
    }

    qDebug() << tr("Network error") << tr("The following error occurred: %1.").arg(tcpClient.errorString());
    remote_socket->close();
    if( !(timer->isActive()) )
    {
        timer->start(RE_TIMEOUT);
        qDebug() << "Timer start";
    }
    emit errorConnection();
}
