#ifndef SCLOCALSERVER_H
#define SCLOCALSERVER_H

#include <QHostAddress>
#include <QDebug>
#include "winsock.h"
#include "stream.h"
#include "crypto.h"
#include "netutils.h"
#include "utils.h"
#include "socks5.h"
#include "remote_client.h"

class ScSocks5Server : public QObject
{
    Q_OBJECT
public:
    explicit ScSocks5Server(ScSetting *st, QTcpSocket *cs, QObject *parent = nullptr);
    ~ScSocks5Server();

    ScStream *e_ctx;
    ScStream *d_ctx;

public slots:
    void readyRead();
    void displayError(QAbstractSocket::SocketError socketError);
    void remoteReadyData(QByteArray *remote_data);

signals:
    void readyData(QByteArray data);

private:
    int serverInit();
    int serverHandshake();
    void serverStream();
    void create_remote(int direct);
    int server_handshake_reply(int udp_assc, struct socks5_response *response);

    QTcpSocket *conn;
    ScRemoteClient *remote_client;
    ScSetting *setting;
    QByteArray buf;
    QByteArray header_buf;
    int stage;
};

#endif // SCLOCALSERVER_H
