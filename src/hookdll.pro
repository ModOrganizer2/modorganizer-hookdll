#-------------------------------------------------
#
# Project created by QtCreator 2011-05-14T17:41:33
#
#-------------------------------------------------

QT       -= core gui

TARGET = hook

TEMPLATE = lib

#DEFINES += HOOKDLL_LIBRARY

!include(../LocalPaths.pri) {
  message("paths to required libraries need to be set up in LocalPaths.pri")
}

SOURCES += \
    utility.cpp \
    stdafx.cpp \
    modinfo.cpp \
    logger.cpp \
    dllmain.cpp \
    disasm_table.cpp \
    disasm.cpp \
    apihook.cpp \
    profile.cpp \
    hooklock.cpp

HEADERS += \
    utility.h \
    stdafx.h \
    reroutes.h \
    modinfo.h \
    logger.h \
    dllmain.h \
    disasm_table.h \
    disasm.h \
    apihook.h \
    profile.h \
    hooklock.h

OTHER_FILES += \
    version.rc

RC_FILE += \
  version.rc

INCLUDEPATH += ../shared ../bsatk "$${BOOSTPATH}"

CONFIG(debug, debug|release) {
  LIBS += -L$$OUT_PWD/../shared/debug -L$$OUT_PWD/../bsatk/debug
  LIBS += -lDbgHelp
  DEFINES += DEBUG
  PRE_TARGETDEPS += $$OUT_PWD/../shared/debug/mo_shared.lib \
    $$OUT_PWD/../bsatk/debug/bsatk.lib
} else {
  LIBS += -L$$OUT_PWD/../shared/release -L$$OUT_PWD/../bsatk/release
  QMAKE_CXXFLAGS += /GL
  QMAKE_LFLAGS += /DEBUG /INCREMENTAL:NO /LTCG /OPT:REF /OPT:ICF
  PRE_TARGETDEPS += $$OUT_PWD/../shared/release/mo_shared.lib \
    $$OUT_PWD/../bsatk/release/bsatk.lib

}

# leak detection with vld
INCLUDEPATH += "E:/Visual Leak Detector/include"
LIBS += -L"E:/Visual Leak Detector/lib/Win32"
#DEFINES += LEAK_CHECK_WITH_VLD

# custom leak detection
LIBS += -lDbgHelp

DEFINES += \
    UNICODE \
    _UNICODE \
    _CRT_SECURE_NO_WARNINGS \
    _WINDLL \
    DEBUG_LOG

#QMAKE_CXXFLAGS += /analyze

QMAKE_CFLAGS_WARN_ON -= -W3
QMAKE_CFLAGS_WARN_ON += -W4

#QMAKE_CXXFLAGS += -GS -RTCs

LIBS += -lmo_shared -lkernel32 -luser32 -lshell32 -ladvapi32 -lshlwapi -lVersion -lbsatk
LIBS += -L"$${ZLIBPATH}/build" -lzlibstatic -L"$${BOOSTPATH}/stage/lib"

QMAKE_POST_LINK += xcopy /y /I $$quote($$SRCDIR\\hook*.dll) $$quote($$DSTDIR) $$escape_expand(\\n)
QMAKE_POST_LINK += xcopy /y /I $$quote($$SRCDIR\\hook*.pdb) $$quote($$DSTDIR) $$escape_expand(\\n)
