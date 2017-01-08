#ifndef TOKENSESSION_H
#define TOKENSESSION_H


#ifdef __unix__
#include <dlfcn.h>
#endif

#ifdef _WIN32
#include <Windows.h>
#endif

#include "Common.h"
#include "enums.h"
#include "texception.h"
#include "pkcsconvert.h"

#include <string>

class TokenSession
{
public:
    TokenSession(void *pFunctionList, void *pExFunctionList);
    ~TokenSession();

    void                            OpenSessionOnSlot(const int64_t slot);
    void                            Login(const int64_t user, std::string &pin);
    void                            Logout();
    void                            CloseSessionsOnSlot();
    void                            Reconnect(const int64_t user, std::string &pin);

    byte_array                      GetTokenSerial();
    bool                            IsSessionOpened();

    void                            *GetFunctionListPtr() { return pFunctionList; }
    void                            *GetExFunctionListPtr() { return pExFunctionList; }
    uint64_t                        GetSessionHandle() { return (uint64_t)hSession; }

private:
    CK_SESSION_HANDLE               hSession;
    CK_FUNCTION_LIST_PTR            pFunctionList;
    CK_FUNCTION_LIST_EXTENDED_PTR   pExFunctionList;
    int64_t                         aSlot;

    void                            preCheck();
    void                            openSessionOnSlot(const int64_t slot);
    void                            closeSessions();
    void                            login(const int64_t user, const std::string &pin);
    void                            logout();
    byte_array                      getSerial();
};

#endif // TOKENSESSION_H
