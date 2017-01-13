#ifndef TKEYSMANAGER_H
#define TKEYSMANAGER_H

#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>
#include "Common.h"
#include "tokensession.h"
#include "enums.h"
#include "texception.h"
#include "pkcsconvert.h"
#include "tcryptomanager.h"

namespace pkcs11_core
{

namespace crypto
{

class TCryptoManager;

class TKeyManager
{
    friend class TCryptoManager;
public:
    TKeyManager(device::TokenSession *tSession);

    byte_array                                  GenerateKeyGOST28147(std::map<Attribute, std::string> &attributes);
    std::vector<std::map<Attribute, std::string>> GetSecretKeyList();
    std::map<Attribute, std::string>            GetSecretKeyAttributes(const byte_array &keyID) { return getKeyAttributes(keyID, CKO_SECRET_KEY); }
    byte_array                                  CreateSecretKey(std::map<Attribute, std::string> &attributes) { return createKey(attributes, CKO_SECRET_KEY, CKK_GOST28147); }

    bool                                        IsSecretKeyExists(const byte_array &keyID);
    void                                        RemoveSecretKey(const byte_array &keyID);
    void                                        RemoveAllKeys();
    void                                        SetSessionHandle(const uint64_t hSession) { this->hSession = (CK_SESSION_HANDLE)hSession; }

    static void                                 FreeAttributesTemplate(std::map<Attribute, std::string> *attributeTmpl);

private:
    void                                        preCheck();
    byte_array                                  createKey(std::map<Attribute, std::string> &attributes, const CK_OBJECT_CLASS objectClass, const CK_KEY_TYPE keyType);
    std::map<Attribute, std::string>            getKeyAttributes(const byte_array &keyID, const CK_OBJECT_CLASS keyClass);
    std::vector<CK_OBJECT_HANDLE>               getKeyHandle(const byte_array &keyID, const CK_OBJECT_CLASS keyClass);
    void                                        overwriteAndFreeAttributes(CK_ATTRIBUTE_PTR attributes);
    void                                        overwriteAndFreeAttributesWithValue(CK_ATTRIBUTE_PTR attributes);
    CK_ATTRIBUTE_PTR                            getAttributeArray(const CK_OBJECT_CLASS objectClass, const CK_KEY_TYPE keyType, std::map<Attribute, std::string> attributes, int64_t *size);
    CK_BYTE_PTR                                 generateId(int64_t *size);


    std::vector<CK_OBJECT_HANDLE>               findKeys(const CK_OBJECT_CLASS objectClass);
    std::vector<std::map<Attribute, std::string>> getKeyList(const CK_OBJECT_CLASS objectClass);
    void                                        removeKey(const byte_array &keyID, const CK_OBJECT_CLASS objectClass);

    device::TokenSession                        *session;
    CK_SESSION_HANDLE                           hSession;
    CK_FUNCTION_LIST_PTR                        pFunctionList;

    const uint64_t                              AttributesMaxCount = 16;

    const uint64_t                              attributeIDSize = 10;

    const uint64_t                              classPosition = 0;
    const uint64_t                              keyTypePosition = 1;
    const uint64_t                              idPosition = 2;
    const uint64_t                              labelPosition = 3;
    const uint64_t                              valuePosition = 4;
    const uint64_t                              gost28147ParamsPosition = 5;
    const uint64_t                              gost3410ParamsPosition = 5;
    const uint64_t                              gost3411ParamsPosition = 6;

    bool                                        bTrue = true;
    bool                                        bFalse = false;

    CK_BYTE                                     GOST3410_params_oid[9] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
    CK_BYTE                                     GOST3411_params_oid[9] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };
    CK_BYTE                                     GOST28147_params_oid[9] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };

};

} // crypto
} // pkcs11_core



#endif // TKEYSMANAGER_H
