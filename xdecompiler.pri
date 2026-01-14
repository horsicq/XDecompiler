INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xdecompiler.h \
    $$PWD/arch/xabstractparser.h \
    $$PWD/arch/xx86parser.h

SOURCES += \
    $$PWD/xdecompiler.cpp \
    $$PWD/arch/xabstractparser.cpp \
    $$PWD/arch/xx86parser.cpp

DISTFILES += \
    $$PWD/xdecompiler.cmake

