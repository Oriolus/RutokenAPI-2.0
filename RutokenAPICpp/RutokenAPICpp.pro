TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    rtpkcs11ecplib.cpp \
    pkcsconvert.cpp \
    tokensession.cpp \
    tokenservant.cpp \
    texception.cpp \
    tkeysmanager.cpp \
    tcryptomanager.cpp

HEADERS += \
    Common.h \
    rtpkcs11ecplib.h \
    pkcsconvert.h \
    tokensession.h \
    tokenservant.h \
    pkcs_types.h \
    enums.h \
    texception.h \
    tkeysmanager.h \
    tcryptomanager.h \
    include_rt/cryptoki.h \
    include_rt/pkcs11.h \
    include_rt/pkcs11f.h \
    include_rt/pkcs11t.h \
    include_rt/rtpkcs11.h \
    include_rt/rtpkcs11f.h \
    include_rt/rtpkcs11t.h \
    include_rt/rtRusPKCS11.h \
    include_rt/win2nix.h \
    include_rt/wintypes.h \
    pkcs11_core.h
