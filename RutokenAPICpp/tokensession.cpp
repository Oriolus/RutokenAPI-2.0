#include "tokensession.h"

#include <iostream>
#include <cstdlib>

pkcs11_core::device::TokenSession::TokenSession(void *pFunctionList, void *pExFunctionList)
{
    if(pFunctionList == nullptr)
    {
        throw new TException("Function list not loaded", Error::FUNCITON_LIST_NOT_LOADED);
    }
    this->pFunctionList = (CK_FUNCTION_LIST_PTR)pFunctionList;
    if(pExFunctionList)
    {
        throw new TException("Extended function list not loaded", Error::FUNCITON_LIST_NOT_LOADED);
    }
    this->pExFunctionList = (CK_FUNCTION_LIST_EXTENDED_PTR)pExFunctionList;

    aSlot = -1;
}

pkcs11_core::device::TokenSession::~TokenSession()
{
    std::cout << "~TokenSession" << std::endl;
    CloseSessionsOnSlot();
}

void pkcs11_core::device::TokenSession::preCheck()
{
    if(pFunctionList == nullptr)
        throw new TException("Function list not loaded", Error::FUNCITON_LIST_NOT_LOADED);
}

void pkcs11_core::device::TokenSession::openSessionOnSlot(const int64_t slot)
{
    preCheck();
    CK_SLOT_ID _slotId = (CK_ULONG)slot;
    CK_RV rv = pFunctionList->C_OpenSession(_slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession);
    if(rv != CKR_OK)
    {
        throw new TException("Openning session exception.", (Error)rv);
    }

    aSlot = slot;
}

void pkcs11_core::device::TokenSession::OpenSessionOnSlot(const int64_t slot)
{
    openSessionOnSlot(slot);
}

byte_array pkcs11_core::device::TokenSession::getSerial()
{
    preCheck();
    if(this->aSlot == -1)
    {
        throw new TException("There is not existing session", Error::SESSION_CLOSED);
    }

    CK_TOKEN_INFO tokenInfo;
    memset(&tokenInfo, 0x00, sizeof(tokenInfo));

    CK_RV rv = pFunctionList->C_GetTokenInfo((CK_SLOT_ID)aSlot, &tokenInfo);
    if(rv != CKR_OK)
    {
        throw new TException("Can't get token info", Error::FUNCTION_FAILED);
    }

    byte_array result((byte*)tokenInfo.serialNumber, (byte*)tokenInfo.serialNumber + sizeof(tokenInfo.serialNumber));
    result = PkcsConvert::TrimBA(result);
    return result;
}

void pkcs11_core::device::TokenSession::login(const int64_t user, const std::string &pin)
{
    preCheck();
    CK_ULONG lPinSize = (CK_ULONG)pin.size();
    CK_RV rv = pFunctionList->C_Login(hSession, user, (CK_UTF8CHAR_PTR)pin.data(), lPinSize);
    if(rv != CKR_OK)
    {
        throw new TException("Can't login with such user and password", Error::FUNCTION_FAILED);
    }
}

void pkcs11_core::device::TokenSession::Login(const int64_t user, std::string &pin)
{
    login(user, pin);
}

void pkcs11_core::device::TokenSession::Logout()
{
    logout();
}

void pkcs11_core::device::TokenSession::logout()
{
    preCheck();

    if(hSession != NULL_PTR)
    {
        CK_RV rv = CKR_FUNCTION_FAILED;
        rv = pFunctionList->C_Logout(hSession);
        if(rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN)
        {
            TException("Logout error.", (Error)rv);
        }
        hSession = NULL_PTR;
    }
}

void pkcs11_core::device::TokenSession::closeSessions()
{
    logout();
    if(aSlot != -1)
    {
        CK_RV rv = CKR_OK;
        rv = pFunctionList->C_CloseAllSessions(aSlot);
        if(rv != CKR_OK)
        {
            throw new TException("Closing sessions error", (Error)rv);
        }
        hSession = NULL_PTR;
    }
}

void pkcs11_core::device::TokenSession::CloseSessionsOnSlot()
{
    logout();
    closeSessions();
    aSlot = -1;
}

void pkcs11_core::device::TokenSession::Reconnect(const int64_t user, std::string &pin)
{
    closeSessions();
    openSessionOnSlot(aSlot);
    login(user, pin);
}

byte_array pkcs11_core::device::TokenSession::GetTokenSerial()
{
    return getSerial();
}

bool pkcs11_core::device::TokenSession::IsSessionOpened()
{
    preCheck();
    if(hSession == NULL_PTR)
    {
        throw new TException("There is not opened session", Error::SESSION_CLOSED);
    }

    CK_RV rv = CKR_OK;
    CK_SESSION_INFO sessionInfo;
    memset(&sessionInfo, 0x00, sizeof(sessionInfo));
    rv = pFunctionList->C_GetSessionInfo(hSession, &sessionInfo);

    return rv == CKR_OK;
}
