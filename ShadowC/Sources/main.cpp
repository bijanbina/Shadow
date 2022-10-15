#include <QApplication>
#include "local.h"

int main(int argc, char *argv[])
{
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

    QApplication app(argc, argv);
    app.setOrganizationName("WBT");
    app.setOrganizationDomain("WBT.com");
    app.setApplicationName("PolyBar");

    ScSetting *setting = new ScSetting();
    setting->local_port = 1088;
    setting->remote_port = 7801;
    setting->password = "pass";
    setting->method = "aes-256-cfb";
    setting->remote_host = "85.10.139.67";

    ScLocal *local = new ScLocal(setting);

    return app.exec();
}
