#include "sc_apache_se.h"

ScApacheSe::ScApacheSe(QString name, QObject *parent):
                       QObject(parent)
{
    con_name = name; // for debug msg
    server = new QTcpServer;
    connect(server, SIGNAL(newConnection()),
            this, SLOT(acceptConnection()));

    mapper_data       = new QSignalMapper(this);
    mapper_error      = new QSignalMapper(this);
    mapper_disconnect = new QSignalMapper(this);

    connect(mapper_data      , SIGNAL(mapped(int)),
            this             , SLOT(readyRead(int)));
    connect(mapper_error     , SIGNAL(mapped(int)),
            this             , SLOT(displayError(int)));
    connect(mapper_disconnect, SIGNAL(mapped(int)),
            this             , SLOT(tcpDisconnected(int)));
}

ScApacheSe::~ScApacheSe()
{
    int len = cons.size();
    for( int i=0 ; i<len ; i++ )
    {
        if( cons[i]==NULL )
        {
            continue;
        }
        if( cons[i]->isOpen() )
        {
            cons[i]->close();
        }
    }
}

void ScApacheSe::bind(int port)
{
    if( server->listen(QHostAddress::Any, port) )
    {
        qDebug() << "created on port " << port;
    }
    else
    {
        qDebug() << "Server failed";
        qDebug() << "Error message is:" << server->errorString();
    }
}

void ScApacheSe::acceptConnection()
{
    if( putInFree() )
    {
        return;
    }
    int new_con_id = cons.length();
    cons.push_back(NULL);
    setupConnection(new_con_id);
}

void ScApacheSe::displayError(int id)
 {
    QString msg = "FaApacheSe::" + con_name;
    msg += " Error";
    qDebug() << msg.toStdString().c_str()
             << id << cons[id]->errorString()
             << cons[id]->state()
             << ipv4[id].toString();

    cons[id]->close();

    qDebug() << "FaApacheSe::displayError," << id;
//    if( cons[id]->error()==QTcpSocket::RemoteHostClosedError )
//    {
//    }
}

void ScApacheSe::tcpDisconnected(int id)
{
    QString msg = "FaApacheSe::" + con_name;
    msg += " disconnected";
    qDebug() << msg.toStdString().c_str() << id
             << ipv4[id].toString();
}

void ScApacheSe::readyRead(int id)
{
    QByteArray data_rx = cons[id]->readAll();

    read_bufs[id] += data_rx;
    qDebug() << "read_bufs::" << read_bufs[id] << data_rx.length();
}

QByteArray ScApacheSe::processBuffer(int id)
{
    if( read_bufs[id].contains(FA_START_PACKET)==0 )
    {
        return "";
    }
    if( read_bufs[id].contains(FA_END_PACKET)==0 )
    {
        return "";
    }
    int start_index = read_bufs[id].indexOf(FA_START_PACKET);
    start_index += strlen(FA_START_PACKET);
    read_bufs[id].remove(0, start_index);

    int end_index = read_bufs[id].indexOf(FA_END_PACKET);
    QByteArray data = read_bufs[id].mid(0, end_index);

    end_index += strlen(FA_END_PACKET);
    read_bufs[id].remove(0, end_index);

    return data;
}

// return id in array where connection is free
int ScApacheSe::putInFree()
{
    int len = cons.length();
    for( int i=0 ; i<len ; i++ )
    {
        if( cons[i]->isOpen()==0 )
        {
            mapper_data->removeMappings(cons[i]);
            mapper_error->removeMappings(cons[i]);
            mapper_disconnect->removeMappings(cons[i]);
            delete cons[i];
            setupConnection(i);

            return 1;
        }
        else
        {
            qDebug() << "conn is open" << i;
        }
    }

    return 0;
}

void ScApacheSe::setupConnection(int con_id)
{
    QTcpSocket *con = server->nextPendingConnection();
    cons[con_id] = con;
    con->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    quint32 ip_32 = con->peerAddress().toIPv4Address();
    QString msg = "FaApacheSe::" + con_name;
    if( con_id<ipv4.length() )
    { // put in free
        ipv4[con_id] = QHostAddress(ip_32);
        read_bufs[con_id].clear();
        msg += " refereshing connection";
    }
    else
    {
        ipv4.push_back(QHostAddress(ip_32));
        read_bufs.push_back(QByteArray());
        msg += " accept connection";
    }
    qDebug() << msg.toStdString().c_str() << con_id
             << ipv4[con_id].toString();

    // readyRead
    mapper_data->setMapping(con, con_id);
    connect(con, SIGNAL(readyRead()), mapper_data, SLOT(map()));

    // displayError
    mapper_error->setMapping(con, con_id);
    connect(con, SIGNAL(error(QAbstractSocket::SocketError)),
            mapper_error, SLOT(map()));

    // disconnected
    mapper_disconnect->setMapping(con, con_id);
    connect(con, SIGNAL(disconnected()),
            mapper_disconnect, SLOT(map()));

    emit connected(con_id);
}
