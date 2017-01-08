#ifndef RTPKCS11ECPLIB_H
#define RTPKCS11ECPLIB_H

#include "Common.h"
#include "texception.h"
#include "enums.h"

#include <string>

class RtPKCS11EcpLib
{
public:
    RtPKCS11EcpLib();
    ~RtPKCS11EcpLib();

    void* GetFunctionListPtr() const { return this->pFunctionList; }
    void* GetExFunctionListPtr() const { return this->pExFunctionList; }

    void LoadPkcsLibrary(const std::string path);
    void FinalizeLib();

private:
    void *hModule;
    CK_FUNCTION_LIST_PTR    pFunctionList;
    CK_FUNCTION_LIST_EXTENDED_PTR pExFunctionList;

    void finalizeLib();


#if defined(_WIN32)
    const LPCWSTR defaultLibPath = L"rtpkcs11ecp.dll";//L"./libs/rtpkcs11ecp.dll";
#elif defined(__unix__)
    cosnt LPCWSTR defaultLibPath = L"./lib/librtpkcs11ecp.so";
#endif
};

#endif // RTPKCS11ECPLIB_H
