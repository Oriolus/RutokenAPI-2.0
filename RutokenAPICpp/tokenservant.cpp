#include "tokenservant.h"

pkcs11_core::device::TokenServant::TokenServant(void *pFunctionList, void *pExFunctionList)
{
    this->pFunctionList = (CK_FUNCTION_LIST_PTR)pFunctionList;
    this->pExFunctionList = (CK_FUNCTION_LIST_EXTENDED_PTR)pExFunctionList;
}

pkcs11_core::device::TokenServant::~TokenServant()
{
    std::cout << "~TokenServant" << std::endl;
}

void pkcs11_core::device::TokenServant::preCheck()
{
    if(pFunctionList == nullptr)
        throw new TException("Function list is not loaded", Error::FUNCITON_LIST_NOT_LOADED);
}

std::vector<pkcs11_core::TokenInfo> pkcs11_core::device::TokenServant::GetTokenList()
{
    return getTokenList();
}

std::vector<pkcs11_core::TokenInfo> pkcs11_core::device::TokenServant::getTokenList()
{
    preCheck();

    CK_RV rv = CKR_OK;
    CK_ULONG ulSlotWithTokenCount = 0;
    CK_SLOT_ID_PTR aSlotWithToken = NULL_PTR;

    rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotWithTokenCount);
    if(rv != CKR_OK)
    {
        throw new TException("Can't get info of slot list", (Error)rv);
    }
    if(ulSlotWithTokenCount == 0)
    {
        return std::vector<TokenInfo>(0);
    }

    aSlotWithToken = new CK_SLOT_ID[ulSlotWithTokenCount];
    rv = pFunctionList->C_GetSlotList(CK_TRUE, aSlotWithToken, &ulSlotWithTokenCount);
    if(rv != CKR_OK)
    {
        delete[] aSlotWithToken;
        throw new TException("Can't get slot list", (Error)rv);
    }
    std::vector<TokenInfo> tInfo(ulSlotWithTokenCount);
    for(size_t i = 0; i < ulSlotWithTokenCount; i++)
    {
        tInfo[i] = getTokenInfo(aSlotWithToken[i]);
    }

    delete[] aSlotWithToken;
    return tInfo;
}

pkcs11_core::TokenInfo pkcs11_core::device::TokenServant::GetTokenInfo(const std::string &serial)
{
    TokenInfo ti;

    int32_t slotId = findTokenOnSlot(serial);
    if(slotId != -1)
        ti = getTokenInfo(slotId);

    return ti;
}

pkcs11_core::TokenInfo pkcs11_core::device::TokenServant::getTokenInfo(int32_t slot)
{
    preCheck();
    if(slot == -1)
    {
        throw new TException("Slot value is invalid", Error::SLOT_ID_INVALID);
    }

    CK_TOKEN_INFO tokenInfo;
    memset(&tokenInfo, 0x00, sizeof(tokenInfo));

    CK_RV rv = pFunctionList->C_GetTokenInfo(slot, &tokenInfo);
    if(rv != CKR_OK)
    {
        throw new TException("Can't get token info", (Error)rv);
    }
    TokenInfo result;

    result.Label = std::string((const char*)tokenInfo.label, (const char*)tokenInfo.label + sizeof(tokenInfo.label));
    result.Label = PkcsConvert::Trim(result.Label);
    result.Serial = std::string((const char*)tokenInfo.serialNumber, (const char*)tokenInfo.serialNumber + sizeof(tokenInfo.serialNumber));
    result.Serial = PkcsConvert::Trim(result.Serial);
    result.Manufacturer = std::string((const char*)tokenInfo.manufacturerID, (const char*)tokenInfo.manufacturerID + sizeof(tokenInfo.manufacturerID));
    result.Manufacturer = PkcsConvert::Trim(result.Manufacturer);
    result.Model = std::string((const char*)tokenInfo.model, (const char*)tokenInfo.model + sizeof(tokenInfo.model));
    result.Model = PkcsConvert::Trim(result.Model);
    result.Flags = (int64_t)tokenInfo.flags;
    result.MaxSessionCount = (int64_t)tokenInfo.ulMaxSessionCount;
    result.CurrentSessionCount = (int64_t)tokenInfo.ulSessionCount;
    result.MaxRWSessionCount = (int64_t)tokenInfo.ulMaxRwSessionCount;
    result.CurrentRWSessionCount = (int64_t)tokenInfo.ulRwSessionCount;
    result.MaxPinLength = (int64_t)tokenInfo.ulMaxPinLen;
    result.MinPinLength = (int64_t)tokenInfo.ulMinPinLen;
    result.TotalPublicMemory = (int64_t)tokenInfo.ulTotalPublicMemory;
    result.TotalPrivateMemory = (int64_t)tokenInfo.ulTotalPrivateMemory;
    result.FreePublicMemory = (int64_t)tokenInfo.ulFreePublicMemory;
    result.FreePrivateMemory = (int64_t)tokenInfo.ulFreePrivateMemory;
    //result.HardwareVersion =
    //result.FirmwareVersion =
    result.Slot = slot;

    return result;
}

int32_t pkcs11_core::device::TokenServant::FinTokenOnSlot(const std::string &serial)
{
    return findTokenOnSlot(serial);
}

int32_t pkcs11_core::device::TokenServant::findTokenOnSlot(const std::string &serial)
{
    std::vector<TokenInfo> tokens = getTokenList();
    for(TokenInfo &ti: tokens)
    {
        if(ti.Serial == serial)
        {
            return (int32_t)ti.Slot;
        }
    }
    return -1;
}
