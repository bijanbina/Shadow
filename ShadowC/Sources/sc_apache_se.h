#ifndef SC_APACHE_H
#define SC_APACHE_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QString>
#include <QObject>
#include <QVector>
#include <stdio.h>
#include <stdlib.h>
#include <QTimer>
#include <QSignalMapper>
#include "backend.h"

#define FA_START_PACKET "<START>\r\n"
#define FA_END_PACKET   "\r\n<END>\r\n"

class ScApacheSe : public QObject
{
    Q_OBJECT

public:
    explicit ScApacheSe(QString name="", QObject *parent = 0);
    ~ScApacheSe();

    void bind(int port);

    QVector<QTcpSocket *> cons;
    QVector<QHostAddress> ipv4;

signals:
    void connected(int id);
    void dataReady(int id, QString data);

public slots:
    void readyRead(int id);
    void acceptConnection();
    void displayError(int id);
    void tcpDisconnected(int id);

private:
    QByteArray processBuffer(int id);
    int  putInFree();
    void setupConnection(int con_id);

    QSignalMapper *mapper_data;
    QSignalMapper *mapper_disconnect;
    QSignalMapper *mapper_error;
    QTcpServer *server;
    QVector<QByteArray> read_bufs;
    QString con_name;
};

#endif // SC_APACHE_H
