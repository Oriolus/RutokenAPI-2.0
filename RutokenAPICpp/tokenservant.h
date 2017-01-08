#ifndef TOKENSERVANT_H
#define TOKENSERVANT_H

#include "Common.h"
#include "pkcs_types.h"
#include "pkcsconvert.h"
#include "texception.h"

#include <vector>
#include <iostream>

class TokenServant
{
public:
    TokenServant(void *pFunctionList, void *pExFunctionList);
    ~TokenServant();

    int32_t                         FinTokenOnSlot(const std::string &serial);
    std::vector<TokenInfo>          GetTokenList();
    TokenInfo                       GetTokenInfo(const std::string &serial);
private:
    void                            preCheck();
    CK_FUNCTION_LIST_PTR            pFunctionList;
    CK_FUNCTION_LIST_EXTENDED_PTR   pExFunctionList;

    std::vector<TokenInfo>          getTokenList();
    TokenInfo                       getTokenInfo(int32_t slot);
    int32_t                         findTokenOnSlot(const std::string &serial);
};

#endif // TOKENSERVANT_H
