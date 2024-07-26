#include "remote_client.h"

ScRemoteClient::ScRemoteClient(ScSetting *st, QObject *parent):
    QObject(parent)
{
    setting = st;
    remote = new QTcpSocket();
    connect(remote, SIGNAL(connected()),
            this,   SLOT  (connected()));
    connect(remote, SIGNAL(disconnected()),
            this,   SLOT  (disconnected()));
    connect(remote, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(displayError(QAbstractSocket::SocketError)));
}

void ScRemoteClient::open()
{
    qDebug() << "ScRemoteClient, connecting to:" << setting->remote_host << setting->remote_port;
    socket->connectToHost(QHostAddress(setting->remote_host), setting->remote_port);
}

void ScRemoteClient::stream()
{
    qDebug() << "stream :" << buf.length();

    int s = socket->write(buf);

    if (s == -1)
    {
        buf.clear();
        qDebug("server_recv_cb_send write err");
        return;
    }
    else if( s<buf.length() )
    {
        buf.remove(0, s);
        return;
    }
    else
    {
        buf.clear();
    }
}

void ScRemoteClient::connected()
{
    qDebug() << "Client: Connected";
    socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(socket, SIGNAL(readyRead()), this, SLOT(readyRead()));
//    timer->stop();

    if( buf.length()==0 )
    {
        qDebug() << "Error: client buf lenght is 0 : ScRemoteClient";
        return;
    }
    else
    {
        // has data to send
        ssize_t s = socket->write(buf);
        qDebug() << "we have data to send"
                 << buf.length() << s;

        if (s == -1)
        {
            qDebug() << "Error: socket->write(buf)";
            return;
        }
        else if( s<buf.length() )
        {
            // partly sent, move memory, wait for the next time to send
            buf.remove(0, s);
            return;
        }
        else
        {
            // all sent out, wait for reading
            buf.clear();
        }
    }
}

void ScRemoteClient::readyRead()
{
   QByteArray read_data = socket->readAll();

   if( read_data.size()==0 )
   {
       return;
   }

   emit readyData(&read_data);
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
    if( socketError==QTcpSocket::RemoteHostClosedError )
    {
        return;
    }

    qDebug() << "Network error The following error occurred"
             << remote->errorString();
    remote->close();

    emit errorConnection();
}
