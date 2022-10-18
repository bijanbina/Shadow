#include "socks5_server.h"
#include <in6addr.h>

ScSocks5Server::ScSocks5Server(ScSetting *st, QTcpSocket *cs, QObject *parent) : QObject(parent)
{
    setting = st;
    conn = cs;
    conn->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    connect(conn, SIGNAL(readyRead()),
            this, SLOT(readyRead()));
    connect(conn, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(displayError(QAbstractSocket::SocketError)));
    stage = STAGE_INIT;
    e_ctx = new ScStream(setting->password);
    d_ctx = new ScStream(setting->password);
    remote_client = NULL;
}

ScSocks5Server::~ScSocks5Server()
{
    ;
}

int ScSocks5Server::serverInit()
{
    qDebug() << "connection from"
             << conn->peerAddress().toString()
             << conn->peerPort();

    if (buf.length() < 1)
    {
        qDebug() << "server_init: len < 1";
        return 1;
    }
    if ( buf.at(0)!=SVERSION )
    {
        qDebug() << "server_init: buf[0]: " << buf.at(0)
                 << "!= SVERSION: " << SVERSION;
        return 1;
    }
    if (buf.length() < sizeof(struct method_select_request))
    {
        return 1;
    }
    struct method_select_request *method = (struct method_select_request *)buf.data();
    int method_len                       = method->nmethods + sizeof(struct method_select_request);
    if( buf.length()<method_len )
    {
        return 1;
    }

    struct method_select_response response;
    response.ver    = SVERSION;
    response.method = METHOD_UNACCEPTABLE;
    for (int i = 0; i < method->nmethods; i++)
    {
        if (method->methods[i] == METHOD_NOAUTH)
        {
            response.method = METHOD_NOAUTH;
            break;
        }
    }
    char *send_buf = (char *)&response;
    conn->write(send_buf, sizeof(response));
    if( response.method==METHOD_UNACCEPTABLE )
    {
        return 1;
    }

    stage = STAGE_HANDSHAKE;

    if( method_len<buf.length() )
    {
        buf.remove(0, method_len);
        return 0;
    }

    buf.clear();
    return 1;
}

int ScSocks5Server::serverHandshake()
{
    struct socks5_request *request = (struct socks5_request *)buf.data();
    size_t request_len             = sizeof(struct socks5_request);

    if( buf.length()<request_len )
    {
        return -1;
    }

    struct socks5_response response;
    response.ver  = SVERSION;
    response.rep  = SOCKS5_REP_SUCCEEDED;
    response.rsv  = 0;
    response.atyp = SOCKS5_ATYP_IPV4;

    if (request->cmd == SOCKS5_CMD_UDP_ASSOCIATE)
    {
        qDebug() << "udp assc request accepted";
        return server_handshake_reply(1, &response);
    }
    else if (request->cmd != SOCKS5_CMD_CONNECT)
    {
        qDebug() << "unsupported command:" << request->cmd;
        response.rep = SOCKS5_REP_CMD_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        conn->write(send_buf, 4);

        return -1;
    }

    header_buf.clear();
    int atyp = request->atyp;
    header_buf.append(atyp);

    // get remote addr and port
    if( atyp==SOCKS5_ATYP_IPV4 )
    {
        size_t in_addr_len = sizeof(struct in_addr);
        if (buf.length() < request_len + in_addr_len + 2)
        {
            return -1;
        }
        header_buf.append(buf.data() + request_len, in_addr_len + 2);
    }
    else if( atyp==SOCKS5_ATYP_DOMAIN )
    {
        uint8_t name_len = *(uint8_t *)(buf.data() + request_len);
        if( buf.length()<request_len+1+name_len+2 )
        {
            return -1;
        }
        header_buf.append(name_len);
        header_buf.append(buf.data() + request_len + 1, name_len + 2);
    }
    else if (atyp == SOCKS5_ATYP_IPV6)
    {
        size_t in6_addr_len = sizeof(struct in6_addr);
        if( buf.length()<request_len+in6_addr_len+2 )
        {
            return -1;
        }
        header_buf.append(buf.data() + request_len, in6_addr_len + 2);
    }
    else
    {
        qDebug() << "unsupported addrtype:" << request->atyp;
        response.rep = SOCKS5_REP_ADDRTYPE_NOT_SUPPORTED;
        char *send_buf = (char *)&response;
        conn->write(send_buf, 4);

        return -1;
    }

    if( server_handshake_reply(0, &response)<0 )
    {
        return -1;
    }
    stage = STAGE_STREAM;

    buf.remove(0,3+header_buf.length());

    // Not bypass
    if( remote_client==NULL )
    {
        create_remote(0);
    }

    if( remote_client==NULL )
    {
        qDebug("invalid remote addr");
        return -1;
    }

    if( !remote_client->direct )
    {
        int err = e_ctx->stream_encrypt(&header_buf);
        if( err )
        {
            qDebug("invalid password or cipher");

            return -1;
        }
    }

    if( buf.length()>0 )
    {
        remote_client->buf = buf;
    }

    if( buf.length()>0 )
    {
        return 0;
    }
    else
    {
//        ev_timer_start(EV_A_ & server->delayed_connect_watcher);
    }

    return -1;
}

void ScSocks5Server::serverStream()
{
    if( remote_client==NULL )
    {
        qDebug("invalid remote");
        return;
    }

    // insert shadowsocks header
    if( !remote_client->direct )
    {

        int err = e_ctx->stream_encrypt(&remote_client->buf);

        if( err )
        {
            qDebug("invalid password or cipher");
            return;
        }

        if( header_buf.length() )
        {
            remote_client->buf.prepend(header_buf);
            header_buf.clear();
        }
    }

    if( !remote_client->socket->isOpen() )
    {
        remote_client->buf.clear();
        remote_client->open();
    }
    else
    {
        remote_client->stream();
    }
}

int ScSocks5Server::server_handshake_reply(int udp_assc, struct socks5_response *response)
{
    if( stage!=STAGE_HANDSHAKE )
    {
        return 0;
    }

    struct sockaddr_in sock_addr;

    buffer_t resp_to_send;
    buffer_t *resp_buf = &resp_to_send;
    balloc(resp_buf, SOCKET_BUF_SIZE);

    memcpy(resp_buf->data, response, sizeof(struct socks5_response));
    memcpy(resp_buf->data + sizeof(struct socks5_response),
           &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
    memcpy(resp_buf->data + sizeof(struct socks5_response) +
           sizeof(sock_addr.sin_addr),
           &sock_addr.sin_port, sizeof(sock_addr.sin_port));

    int reply_size = sizeof(struct socks5_response) +
                     sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);

    int s = conn->write(resp_buf->data, reply_size);

    bfree(resp_buf);

    if (s < reply_size)
    {
        qDebug("failed to send fake reply");
        return -1;
    }
    if (udp_assc)
    {
        // Wait until client closes the connection
        return -1;
    }
    return 0;
}

void ScSocks5Server::create_remote(int direct)
{
    remote_client = new ScRemoteClient(setting);
    remote_client->direct = direct;
    connect(remote_client, SIGNAL(readyData(QByteArray *)), this, SLOT(remoteReadyData(QByteArray *)));

    qDebug() << "remote:" << setting->remote_host << setting->remote_port;
}

void ScSocks5Server::remoteReadyData(QByteArray *remote_data)
{
    buf = *remote_data;

    if( !remote_client->direct )
    {
        int err = d_ctx->stream_decrypt(&buf);
        if (err == CRYPTO_ERROR)
        {
            qDebug("invalid password or cipher");
            return;
        }
        else if (err == CRYPTO_NEED_MORE)
        {
            return; // Wait for more
        }
    }

    int s = conn->write(buf);

    if( s==-1 )
    {
        buf.clear();
        qDebug("remote_recv_cb_send");
        return;
    }
    else if( s<buf.length() )
    {
        buf.remove(0, s);
    }
}

void ScSocks5Server::readyRead()
{
    buf += conn->readAll();

    while(1)
    {
        // local socks5 server
        if( stage==STAGE_INIT )
        {
            int ret = serverInit();
            if( ret )
            {
                return;
            }
        }
        else if( stage==STAGE_HANDSHAKE )
        {
            int ret = serverHandshake();
            if( ret )
            {
                return;
            }
        }
        else if( stage==STAGE_STREAM )
        {
            serverStream();

            // all processed
            return;
        }
    }


//    qDebug() << QString("Ack, Receive Byte: %1").arg(bytesReceived);
//    connection_socket->write("a",1);
//    connection_socket->waitForBytesWritten(50);
    emit readyData(buf);
}

void ScSocks5Server::displayError(QAbstractSocket::SocketError socketError)
{
    if( socketError==QTcpSocket::RemoteHostClosedError )
    {
        return;
    }

    qDebug() << QString("Error Happened");
}
