#ifndef SC_REMOTECLIENT_H
#define SC_REMOTECLIENT_H

#include <QTcpServer>
#include <QTcpSocket>
#include "common.h"

class ScRemoteClient : public QObject
{
    Q_OBJECT
public:
    explicit ScRemoteClient(ScSetting *st,
                            QObject *parent = nullptr);
    void open();
    void stream();

    QTcpSocket *remote;
    QByteArray  buf;
    int direct;

signals:
    void errorConnection();
    void readyData(QByteArray *read_data);

private slots:
    void connected();
    void disconnected();
    void displayError(QAbstractSocket::SocketError socketError);
    void readyRead();

private:
    ScSetting *setting;
};

#endif // SC_REMOTECLIENT_H
