#include "rtpkcs11ecplib.h"

#include <iostream>

RtPKCS11EcpLib::RtPKCS11EcpLib()
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
/*
    CK_C_EX_GetFunctionListExtended pfGetFunctionListEx = nullptr;

#ifdef __unix__
#endif
#ifdef _WIN32
    pfGetFunctionListEx = (CK_C_EX_GetFunctionListExtended)(GetProcAddress((HMODULE)hModule, "C_EX_GetFunctionListExtended"));
#endif

    if(pfGetFunctionListEx == nullptr)
    {
        finalizeLib();
        throw new TException("Extended function list not loaded", Error::FUNCITON_LIST_NOT_LOADED);
    }

    rv = pfGetFunctionListEx(&pExFunctionList);
    if(rv != CKR_OK)
    {
        finalizeLib();
        throw new TException("Extended function list not initialized", Error::FUNCTION_LIST_NOT_INITIALIZED);
    }
*/
    rv = pFunctionList->C_Initialize(nullptr);
    if(rv != CKR_OK)
    {
        finalizeLib();
        throw new TException("Function list not initialized", Error::FUNCTION_LIST_NOT_INITIALIZED);
    }
}

RtPKCS11EcpLib::~RtPKCS11EcpLib()
{
    std::cout << "~RtPKCS11EcpLib" << std::endl;
    finalizeLib();
}

void RtPKCS11EcpLib::LoadPkcsLibrary(const std::string path)
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
/*
    CK_C_EX_GetFunctionListExtended pfGetFunctionListEx = nullptr;

#ifdef __unix__
#endif
#ifdef _WIN32
    pfGetFunctionListEx = (CK_C_EX_GetFunctionListExtended)(GetProcAddress((HMODULE)hModule, "C_EX_GetFunctionListExtended"));
#endif

    if(pfGetFunctionListEx == nullptr)
    {
        finalizeLib();
        throw new TException("Extended function list not loaded", Error::FUNCITON_LIST_NOT_LOADED);
    }

    rv = pfGetFunctionListEx(&pExFunctionList);
    if(rv != CKR_OK)
    {
        finalizeLib();
        throw new TException("Extended function list not initialized", Error::FUNCTION_LIST_NOT_INITIALIZED);
    }
*/
    rv = pFunctionList->C_Initialize(nullptr);
    if(rv != CKR_OK)
    {
        finalizeLib();
        throw new TException("Function list not initialized", Error::FUNCTION_LIST_NOT_INITIALIZED);
    }
}

void RtPKCS11EcpLib::FinalizeLib()
{
    finalizeLib();
}

void RtPKCS11EcpLib::finalizeLib()
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
