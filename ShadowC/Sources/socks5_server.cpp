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
    qDebug() << "serverInit from"
             << conn->peerAddress().toString()
             << conn->peerPort();

    if (soc_buf.length() < 1)
    {
        qDebug() << "server_init: len < 1";
        return 1;
    }
    if ( soc_buf.at(0)!=SVERSION )
    {
        qDebug() << "server_init: buf[0]: " << soc_buf.at(0)
                 << "!= SVERSION: " << SVERSION;
        return 1;
    }
    if (soc_buf.length() < sizeof(struct method_select_request))
    {
        return 1;
    }
    struct method_select_request *method = (struct method_select_request *)soc_buf.data();
    int method_len                       = method->nmethods + sizeof(struct method_select_request);
    if( soc_buf.length()<method_len )
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

    if( method_len<soc_buf.length() )
    {
        soc_buf.remove(0, method_len);
        return 0;
    }

    soc_buf.clear();
    return 1;
}

int ScSocks5Server::serverHandshake()
{
    struct socks5_request *request = (struct socks5_request *)soc_buf.data();
    size_t request_len             = sizeof(struct socks5_request);

    if( soc_buf.length()<request_len )
    {
        qDebug() << "Error: buf length is small";
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
        qDebug() << "SOCKS5_ATYP_IPV4 addrtype:" << request->cmd;
        if (soc_buf.length() < request_len + in_addr_len + 2)
        {
            qDebug() << "Error: buf length is small : SOCKS5_ATYP_IPV4";
            return -1;
        }
        header_buf.append(soc_buf.data() + request_len, in_addr_len + 2);
    }
    else if( atyp==SOCKS5_ATYP_DOMAIN )
    {
        qDebug() << "SOCKS5_ATYP_DOMAIN addrtype:";
        uint8_t name_len = *(uint8_t *)(soc_buf.data() + request_len);
        if( soc_buf.length()<request_len+1+name_len+2 )
        {
            qDebug() << "Error: buf length is small : SOCKS5_ATYP_DOMAIN";
            return -1;
        }
        header_buf.append(name_len);
        header_buf.append(soc_buf.data() + request_len + 1, name_len + 2);
    }
    else if (atyp == SOCKS5_ATYP_IPV6)
    {
        qDebug() << "SOCKS5_ATYP_IPV6 addrtype:";
        size_t in6_addr_len = sizeof(struct in6_addr);
        if( soc_buf.length()<request_len+in6_addr_len+2 )
        {
            qDebug() << "Error: buf length is small : SOCKS5_ATYP_IPV6";
            return -1;
        }
        header_buf.append(soc_buf.data() + request_len, in6_addr_len + 2);
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

    soc_buf.remove(0,3+header_buf.length());

    // Not bypass
    if( remote_client==NULL )
    {
        qDebug() << "creating remote_client";
        create_remote(0);
    }

    if( remote_client==NULL )
    {
        qDebug("invalid remote addr");
        return -1;
    }

    if( !remote_client->direct )
    {
        uint16_t port;
        port = (uint8_t)header_buf.at(5) << 8;
        port += (uint8_t)header_buf.at(6);
        qDebug() << "serverHandshake: header_buf(UNENC)"
                 << port << header_buf.length();
        chertChapkon(&header_buf);
        int err = e_ctx->stream_encrypt(&header_buf);
        chertChapkon(&header_buf);
        if( err )
        {
            qDebug("invalid password or cipher");

            return -1;
        }
    }

    if( soc_buf.length()>0 )
    {
        qDebug() << "server Handshake: buf length > 0";
        remote_client->socket->write(soc_buf);
        return 0;
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
        qDebug() << "server stream: rc_buf" << remote_client->buf.length();
        int err = e_ctx->stream_encrypt(&remote_client->buf);

        if( err )
        {
            qDebug("invalid password or cipher");
            return;
        }

        if( header_buf.length() )
        {
            qDebug() << "serverStream : header_buf";
            remote_client->buf.prepend(header_buf);
            header_buf.clear();
        }
    }

    if( remote_client->socket->isOpen() )
    {
        qDebug() << "remote_client->stream()";
        remote_client->stream();
    }
    else
    {
        qDebug() << "sever stream: remote is not open";
        remote_client->open();
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
    soc_buf = *remote_data;

    if( !remote_client->direct )
    {
        int err = d_ctx->stream_decrypt(&soc_buf);
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

    int s = conn->write(soc_buf);

    if( s==-1 )
    {
        soc_buf.clear();
        qDebug("remote_recv_cb_send");
        return;
    }
    else if( s<soc_buf.length() )
    {
        soc_buf.remove(0, s);
    }
}

void ScSocks5Server::readyRead()
{
    QByteArray read_data = conn->readAll();

    if( remote_client==NULL )
    {
       soc_buf.append(read_data);
       qDebug() << "readyRead: soc_buf" << soc_buf.length();
    }
    else
    {
        remote_client->buf.append(read_data);
        qDebug() << "readyRead: soc_buf(remote)" << remote_client->buf.length();
    }

    while(1)
    {
        // local socks5 server
        if( stage==STAGE_INIT )
        {
            int ret = serverInit();
            qDebug()<< "Stage init"<< ret;
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

            return;
        }
    }
}

void ScSocks5Server::displayError(QAbstractSocket::SocketError socketError)
{
    if( socketError==QTcpSocket::RemoteHostClosedError )
    {
        return;
    }

    qDebug() << QString("Error Happened");
}

void ScSocks5Server::chertChapkon(QByteArray *data)
{
    int i;
    QString lolo;

    lolo += "length =" + QString::number(data->length()) + "; ";
    for ( i=0 ; i< data->length() ; i++)
    {
        if( data->at(i)>31 && data->at(i)<128 )
        {
            lolo += data->at(i);
        }
        else
        {
            lolo += "*";
        }
    }
    qDebug() << "chert_print:" << lolo;
}
