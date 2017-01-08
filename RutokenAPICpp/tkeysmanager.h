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

class TCryptoManager;

using std::string;
using std::map;
using std::vector;

class TKeyManager
{
    friend class TCryptoManager;
public:
    TKeyManager(TokenSession *tSession);

    string                                      GenerateKeyGOST28147(map<Attribute, string> &attributes);
    vector<map<Attribute, string>>              GetSecretKeyList();
    map<Attribute, string>                      GetSecretKeyAttributes(const string &keyID) { return getKeyAttributes(keyID, CKO_SECRET_KEY); }
    string                                      CreateSecretKey(map<Attribute, string> &attributes) { return createKey(attributes, CKO_SECRET_KEY, CKK_GOST28147); }

    bool                                        IsSecretKeyExists(const string &keyID);
    void                                        RemoveSecretKey(const string &keyID);
    void                                        RemoveAllKeys();
    void                                        SetSessionHandle(const uint64_t hSession) { this->hSession = (CK_SESSION_HANDLE)hSession; }

    static void                                 FreeAttributesTemplate(map<Attribute, string> *attributeTmpl);

private:
    void                                        preCheck();
    string                                      createKey(map<Attribute, string> &attributes, const CK_OBJECT_CLASS objectClass, const CK_KEY_TYPE keyType);
    map<Attribute, string>                      getKeyAttributes(const string &keyID, const CK_OBJECT_CLASS keyClass);
    vector<CK_OBJECT_HANDLE>                    getKeyHandle(const string &keyID, const CK_OBJECT_CLASS keyClass);
    void                                        overwriteAndFreeAttributes(CK_ATTRIBUTE_PTR attributes);
    void                                        overwriteAndFreeAttributesWithValue(CK_ATTRIBUTE_PTR attributes);
    CK_ATTRIBUTE_PTR                            getAttributeArray(const CK_OBJECT_CLASS objectClass, const CK_KEY_TYPE keyType, map<Attribute, string> attributes, int64_t *size);
    CK_BYTE_PTR                                 generateId(int64_t *size);

    vector<CK_OBJECT_HANDLE>                    findKeys(const CK_OBJECT_CLASS objectClass);
    vector<map<Attribute, string>>              getKeyList(const CK_OBJECT_CLASS objectClass);
    void                                        removeKey(const string &keyID, const CK_OBJECT_CLASS objectClass);

    TokenSession                                *session;
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

#endif // TKEYSMANAGER_H
