#include <QCoreApplication>
#include "local.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setOrganizationName("WBT");
    app.setOrganizationDomain("WBT.com");
    app.setApplicationName("PolyBar");

    ScSetting *setting = new ScSetting();
    setting->is_server   = 0;
    setting->local_port  = 1088;
    setting->remote_port = 5512;
    setting->password    = "pass";
//    setting->method    = "aes-256-cfb";
    setting->remote_host = "5.255.113.20";

    if( argc>1 )
    {
        setting->is_server = 1;
    }
    ScLocal local(setting);

    return app.exec();
}
