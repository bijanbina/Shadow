TEMPLATE = app

QT += core network
CONFIG += console

MOC_DIR = Build/.moc
RCC_DIR = Build/.rcc
OBJECTS_DIR = Build/.obj
UI_DIR = Build/.ui

HEADERS += \
    Sources/backend.h \
    Sources/local.h \
    Sources/remote_client.h \
    Sources/sc_apache_se.h

win32:HEADERS += \
    Sources/base64.h \
    Sources/crypto.h \
    Sources/netutils.h \
    Sources/qaesencryption.h \
    Sources/shadowsocks.h \
    Sources/socks5.h \
    Sources/socks5_server.h \
    Sources/stream.h \
    Sources/uthash.h \
    Sources/utils.h

SOURCES += \
    Sources/local.cpp \
    Sources/main.cpp \
    Sources/remote_client.cpp \
    Sources/sc_apache_se.cpp

win32:SOURCES += \
    Sources/base64.cpp \
    Sources/crypto.cpp \
    Sources/netutils.cpp \
    Sources/qaesencryption.cpp \
    Sources/socks5_server.cpp \
    Sources/stream.cpp \
    Sources/utils.cpp
