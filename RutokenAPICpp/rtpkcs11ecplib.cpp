#include "rtpkcs11ecplib.h"

#include <iostream>

pkcs11_core::lib::RtPKCS11EcpLib::RtPKCS11EcpLib()
{
    this->pFunctionList = nullptr;
    this->pExFunctionList = nullptr;

    CK_RV rv = CKR_OK;

#ifdef __unix__

#endif
#ifdef _WIN32
    hModule = LoadLibrary(this->defaultLibPath);
#endif

    if(hModule == nullptr)
    {
        throw new TException("Library not loaded", Error::LIBRARI_NOT_LOADED);
    }

    CK_C_GetFunctionList pfGetFunctionList = nullptr;

#ifdef __unix__
#endif
#ifdef _WIN32
    pfGetFunctionList = (CK_C_GetFunctionList)(GetProcAddress((HMODULE)hModule, "C_GetFunctionList"));
#endif

    if(pfGetFunctionList == nullptr)
    {
        finalizeLib();
        throw new TException("Function list not loaded", Error::FUNCITON_LIST_NOT_LOADED);
    }

    rv = pfGetFunctionList(&pFunctionList);
    if(rv != CKR_OK)
    {
        finalizeLib();
        throw new TException("Function list not initialized", Error::FUNCTION_LIST_NOT_INITIALIZED);
    }

    rv = pFunctionList->C_Initialize(nullptr);
    if(rv != CKR_OK)
    {
        finalizeLib();
        throw new TException("Function list not initialized", Error::FUNCTION_LIST_NOT_INITIALIZED);
    }
}

pkcs11_core::lib::RtPKCS11EcpLib::~RtPKCS11EcpLib()
{
    std::cout << "~RtPKCS11EcpLib" << std::endl;
    finalizeLib();
}

void pkcs11_core::lib::RtPKCS11EcpLib::LoadPkcsLibrary(const std::string path)
{
    if(hModule != nullptr)
        finalizeLib();

    CK_RV rv = CKR_OK;

    std::wstring tmps = std::wstring(path.begin(), path.end());
    LPCWSTR loadingPath = tmps.c_str();

#ifdef __unix__

#endif
#ifdef _WIN32
    hModule = LoadLibrary(loadingPath);
#endif

    if(hModule == nullptr)
    {
        return;
        //an error. Use throw
    }

    CK_C_GetFunctionList pfGetFunctionList = nullptr;

#ifdef __unix__
#endif
#ifdef _WIN32
    pfGetFunctionList = (CK_C_GetFunctionList)(GetProcAddress((HMODULE)hModule, "C_GetFunctionList"));
#endif

    if(pfGetFunctionList == nullptr)
    {
        finalizeLib();
        throw new TException("Function list not loaded", Error::FUNCITON_LIST_NOT_LOADED);
    }

    rv = pfGetFunctionList(&pFunctionList);
    if(rv != CKR_OK)
    {
        finalizeLib();
        throw new TException("Function list not initialized", Error::FUNCTION_LIST_NOT_INITIALIZED);
    }
    rv = pFunctionList->C_Initialize(nullptr);
    if(rv != CKR_OK)
    {
        finalizeLib();
        throw new TException("Function list not initialized", Error::FUNCTION_LIST_NOT_INITIALIZED);
    }
}

void pkcs11_core::lib::RtPKCS11EcpLib::finalizeLib()
{
    if(pFunctionList != nullptr)
        pFunctionList->C_Finalize(nullptr);

    pFunctionList = nullptr;

    if(hModule != nullptr)
    {
#ifdef __unix__
        dlclose(hModule);
#endif
#ifdef _WIN32
        FreeLibrary((HMODULE)hModule);
#endif
    }
    hModule = nullptr;
}

void pkcs11_core::lib::RtPKCS11EcpLib::FinalizeLib()
{
    finalizeLib();
}


