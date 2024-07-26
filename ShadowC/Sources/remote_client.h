#ifndef SC_REMOTECLIENT_H
#define SC_REMOTECLIENT_H

#include <QTcpServer>
#include <QTcpSocket>
#include "backend.h"

class ScRemoteClient : public QObject
{
    Q_OBJECT
public:
    explicit ScRemoteClient(ScSetting *st,
                            QObject *parent = nullptr);
    void open();
    void writeBuf();

    QTcpSocket *remote;
    QByteArray  buf;
    int         direct;

private slots:
    void disconnected();
    void displayError(QAbstractSocket::SocketError socketError);

private:
    ScSetting *setting;
};

#endif // SC_REMOTECLIENT_H
