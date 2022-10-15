#ifndef SCREMOTECLIENT_H
#define SCREMOTECLIENT_H

#include <QTcpServer>
#include <QTcpSocket>
#include "common.h"

class ScRemoteClient : public QObject
{
    Q_OBJECT
public:
    explicit ScRemoteClient(ScSetting *st, QObject *parent = nullptr);

    int direct;

signals:
    void errorConnection();
    void newKey(QString key);

private slots:
    void connected();
    void disconnected();
    void displayError(QAbstractSocket::SocketError socketError);
    void readyRead();

private:
    QTcpSocket *remote_socket;
};

#endif // SCREMOTECLIENT_H
