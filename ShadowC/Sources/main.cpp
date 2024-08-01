#include <QCoreApplication>
#include "local.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setOrganizationName("WBT");
    app.setOrganizationDomain("WBT.com");
    app.setApplicationName("PolyBar");

    ScSetting *setting = new ScSetting();
    setting->tx_count    = 0;
    setting->local_port  = 1088;
    setting->remote_port = 5512;
    setting->password    = "pass";
//    setting->method    = "aes-256-cfb";
    setting->remote_host = "5.255.113.20";

    if( argc>1 )
    {
        QString count = argv[1];
        setting->tx_count = count.toInt();
    }
    ScLocal local(setting);

    return app.exec();
}
