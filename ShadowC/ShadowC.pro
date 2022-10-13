TEMPLATE = app

QT += qml quick dbus core websockets

CONFIG += console

win32:QT += gamepad

#RESOURCES += Qml/ui.qrc \
#             Resources/images.qrc \
#             Resources/fonts.qrc

#OTHER_FILES += Qml/*.qml


#linux:INCLUDEPATH += /usr/include/glib-2.0 \
#                     /usr/lib/glib-2.0/include

#linux:LIBS += -lX11 \
#              -lgio-2.0 \
#              -lgobject-2.0 \
#              -lglib-2.0

#win32:LIBS += -L../../Benjamin/PNN/libs \
#              -lKernel32 -lUser32 -lole32 \
#              -luuid -loleaut32 -loleacc \
#              -lDwmapi -lPsapi -lSetupapi \
#              -llua54

#win32:INCLUDEPATH += ../../Benjamin/PNN/lua

#win32:RC_FILE = rebound.rc

QMAKE_CXXFLAGS += -std=c++17
# Additional import path used to resolve QML modules in Qt Creator's code model
QML_IMPORT_PATH += Qml/

DISTFILES += \
    Rebound.exe.manifest

MOC_DIR = Build/.moc
RCC_DIR = Build/.rcc
OBJECTS_DIR = Build/.obj
UI_DIR = Build/.ui

HEADERS += \
    Sources/base64.h \
    Sources/cache.h \
    Sources/common.h \
    Sources/crypto.h \
    Sources/jconf.h \
    Sources/local.h \
    Sources/netutils.h \
    Sources/plusaes/plusaes.hpp \
    Sources/ppbloom.h \
    Sources/resolv.h \
    Sources/rule.h \
    Sources/shadowsocks.h \
    Sources/socks5.h \
    Sources/stream.h \
    Sources/uthash.h \
    Sources/utils.h \
    Sources/winsock.h

SOURCES += \
    Sources/base64.cpp \
    Sources/cache.cpp \
    Sources/crypto.cpp \
    Sources/jconf.cpp \
    Sources/local.cpp \
    Sources/netutils.cpp \
    Sources/ppbloom.cpp \
    Sources/resolv.cpp \
    Sources/rule.cpp \
    Sources/stream.cpp \
    Sources/utils.cpp \
    Sources/winsock.cpp


