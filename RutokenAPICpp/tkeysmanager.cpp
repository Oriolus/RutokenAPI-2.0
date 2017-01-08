#include "tkeysmanager.h"

TKeyManager::TKeyManager(TokenSession *tSession)
{
    srand(time(0));
    session = tSession;
    hSession = (CK_SESSION_HANDLE)tSession->GetSessionHandle();
    pFunctionList = (CK_FUNCTION_LIST_PTR)tSession->GetFunctionListPtr();
}

void TKeyManager::preCheck()
{
    if(hSession == NULL_PTR)
    {
        throw new TException("There is not opened session", Error::SESSION_HANDLE_INVALID);
    }
    if(pFunctionList == nullptr)
    {
        throw new TException("Function list not loaded", Error::FUNCITON_LIST_NOT_LOADED);
    }
}

byte_array TKeyManager::createKey(map<Attribute, string> &attributes, const CK_OBJECT_CLASS objectClass, const CK_KEY_TYPE keyType)
{
    preCheck();

    int64_t lAttributeTmplSize = 0;
    CK_ATTRIBUTE_PTR apAttributeTmpl = getAttributeArray(objectClass, keyType, attributes, &lAttributeTmplSize);
    CK_OBJECT_HANDLE hKeyObject = NULL_PTR;
    CK_RV rv = pFunctionList->C_CreateObject(hSession, apAttributeTmpl, lAttributeTmplSize, &hKeyObject);
    overwriteAndFreeAttributesWithValue(apAttributeTmpl);
    delete[] apAttributeTmpl;
    if(rv != CKR_OK)
    {
        throw new TException("Can't create object", (Error)rv);
    }

    return byte_array(attributes[Attribute::ID].begin(), attributes[Attribute::ID].end());
}

map<Attribute, string> TKeyManager::getKeyAttributes(const byte_array &keyID, const CK_OBJECT_CLASS keyClass)
{
    preCheck();
    if(!(keyClass != CKO_PRIVATE_KEY || keyClass != CKO_PUBLIC_KEY || keyClass != CKO_SECRET_KEY))
    {
        throw new TException("Unknown key class", Error::UNKNOWN_KEY_CLASS);
    }

   vector<CK_OBJECT_HANDLE> keyHandels = getKeyHandle(keyID, keyClass);
   if(keyHandels.size() == 0)
   {
       throw new TException("Key handle not found", Error::KEY_HANDLE_HOT_FOUND);
   }
   else if(keyHandels.size() > 1)
   {
       throw new TException("Too many handles found", Error::MANY_HANDLES_FOUND);
   }

   CK_ATTRIBUTE_PTR apAttributesTmpl = new CK_ATTRIBUTE[this->AttributesMaxCount];
   apAttributesTmpl[classPosition] = { CKA_CLASS, NULL_PTR, 0 };
   apAttributesTmpl[keyTypePosition] = { CKA_KEY_TYPE, NULL_PTR, 0 };
   apAttributesTmpl[idPosition] = { CKA_ID, NULL_PTR, 0 };
   apAttributesTmpl[labelPosition] = { CKA_LABEL, NULL_PTR, 0 };
   apAttributesTmpl[valuePosition] = { CKA_VALUE, NULL_PTR, 0 };

   int lResultCount = 6;
   if(keyClass == CKO_SECRET_KEY)
   {
       apAttributesTmpl[gost28147ParamsPosition] = { CKA_GOST28147_PARAMS, NULL_PTR, 0 };
   }
   else
   {
       apAttributesTmpl[gost3411ParamsPosition] = { CKA_GOSTR3411_PARAMS, NULL_PTR, 0 };
       apAttributesTmpl[gost3410ParamsPosition] = { CKA_GOSTR3410_PARAMS, NULL_PTR, 0 };
       lResultCount = 7;
   }

   apAttributesTmpl[lResultCount++] = { CKA_TOKEN, NULL_PTR, 0 };
   apAttributesTmpl[lResultCount++] = { CKA_PRIVATE, NULL_PTR, 0 };
   apAttributesTmpl[lResultCount++] = { CKA_MODIFIABLE, NULL_PTR, 0 };

   switch(keyClass)
   {
   case CKO_PRIVATE_KEY:
       apAttributesTmpl[lResultCount++] = { CKA_DECRYPT, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_SIGN, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_SENSITIVE, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_EXTRACTABLE, NULL_PTR, 0 };
       break;
   case CKO_PUBLIC_KEY:
       apAttributesTmpl[lResultCount++] = { CKA_ENCRYPT, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_VERIFY, NULL_PTR, 0 };
       break;
   case CKO_SECRET_KEY:
       apAttributesTmpl[lResultCount++] = { CKA_ENCRYPT, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_DECRYPT, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_SIGN, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_VERIFY, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_SENSITIVE, NULL_PTR, 0 };
       apAttributesTmpl[lResultCount++] = { CKA_EXTRACTABLE, NULL_PTR, 0 };
       break;
   }

    CK_RV rv = pFunctionList->C_GetAttributeValue(hSession, keyHandels[0], apAttributesTmpl, lResultCount);
    if(rv != CKR_OK)
    {
        delete[] apAttributesTmpl;
        throw new TException("Can't get attributes size", (Error)rv);
    }

    for(size_t i = 0; i < lResultCount; i++)
    {
        apAttributesTmpl[i].pValue = new CK_BYTE[apAttributesTmpl[i].ulValueLen];
        memset(apAttributesTmpl[i].pValue, 0x00, apAttributesTmpl[i].ulValueLen);
    }

    rv = pFunctionList->C_GetAttributeValue(hSession, keyHandels[0], apAttributesTmpl, lResultCount);
    if(rv != CKR_OK)
    {
        for(size_t i = 0; i < lResultCount; i++)
        {
            if(apAttributesTmpl[i].pValue != nullptr)
                delete[] apAttributesTmpl[i].pValue;
        }
        delete[] apAttributesTmpl;
        throw new TException("Can't get attributes values", (Error)rv);
    }

    map<Attribute, string> result;

    result.insert(std::pair<Attribute, string>(Attribute::ID, string((const char*)apAttributesTmpl[idPosition].pValue, apAttributesTmpl[idPosition].ulValueLen)));
    result.insert(std::pair<Attribute, string>(Attribute::LABEL, string((const char*)apAttributesTmpl[labelPosition].pValue, apAttributesTmpl[labelPosition].ulValueLen)));
    result.insert(std::pair<Attribute, string>(Attribute::VALUE, string((const char*)apAttributesTmpl[valuePosition].pValue, apAttributesTmpl[valuePosition].ulValueLen)));
    size_t lResult = 6;
    if(keyClass == CKO_SECRET_KEY)
    {
        result.insert(std::pair<Attribute, string>(Attribute::GOST28147_PARAMS, string((const char*)apAttributesTmpl[gost28147ParamsPosition].pValue, apAttributesTmpl[gost28147ParamsPosition].ulValueLen)));
    }
    else
    {
        result.insert(std::pair<Attribute, string>(Attribute::GOST3410_PARAMS, string((const char*)apAttributesTmpl[gost3410ParamsPosition].pValue, apAttributesTmpl[gost3410ParamsPosition].ulValueLen)));
        result.insert(std::pair<Attribute, string>(Attribute::GOST3411_PARAMS, string((const char*)apAttributesTmpl[gost3411ParamsPosition].pValue, apAttributesTmpl[gost3411ParamsPosition].ulValueLen)));
        lResult = 7;
    }

    result.insert(std::pair<Attribute, string>(Attribute::TOKEN_, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
    result.insert(std::pair<Attribute, string>(Attribute::PRIVATE, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
    result.insert(std::pair<Attribute, string>(Attribute::MODIFIABLE, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));

    switch(keyClass)
    {
    case CKO_PRIVATE_KEY:
        result.insert(std::pair<Attribute, string>(Attribute::DECRYPT, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::SIGN, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::SENSITIVE, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::EXTRACTABLE, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        break;
    case CKO_PUBLIC_KEY:
        result.insert(std::pair<Attribute, string>(Attribute::ENCRYPT, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::VERIFY, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        break;
    case CKO_SECRET_KEY:
        result.insert(std::pair<Attribute, string>(Attribute::DECRYPT, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::ENCRYPT, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::SIGN, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::VERIFY, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::SENSITIVE, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        result.insert(std::pair<Attribute, string>(Attribute::EXTRACTABLE, PkcsConvert::Bool2Str(*(bool*)apAttributesTmpl[lResult++].pValue)));
        break;
    }

   for(size_t i = 0; i < lResultCount; i++)
   {
       if(apAttributesTmpl[i].pValue != nullptr)
       {
            memset((CK_BYTE_PTR)apAttributesTmpl[i].pValue, 0x00, apAttributesTmpl[i].ulValueLen);
            delete[] (CK_BYTE_PTR)apAttributesTmpl[i].pValue;
       }
   }
   delete[] apAttributesTmpl;

   return result;
}

vector<CK_OBJECT_HANDLE> TKeyManager::getKeyHandle(const byte_array &keyID, const CK_OBJECT_CLASS keyClass)
{
    preCheck();

    CK_RV rv = CKR_OK;
    int64_t ulKeyIdLen = keyID.size();
    CK_OBJECT_CLASS ocKey = keyClass;
    CK_ATTRIBUTE searchForIdAttr[] =
    {
      { CKA_CLASS, &ocKey, sizeof(CK_OBJECT_CLASS) },
      { CKA_ID, (CK_BYTE_PTR)keyID.data(), (CK_ULONG)ulKeyIdLen }
    };

    rv = pFunctionList->C_FindObjectsInit(hSession, searchForIdAttr, arraysize(searchForIdAttr));
    if(rv != CKR_OK)
    {
        throw new TException("Can't initialize search object operation", (Error)rv);
    }

    CK_ULONG lHandleCount = 0;
    CK_OBJECT_HANDLE_PTR pHandles = new CK_OBJECT_HANDLE[64];
    memset(pHandles, 0x00, 64 * sizeof(CK_OBJECT_HANDLE));
    rv = pFunctionList->C_FindObjects(hSession, pHandles, 64, &lHandleCount);
    if(rv != CKR_OK)
    {
        pFunctionList->C_FindObjectsFinal(hSession);
        delete[] pHandles;
        throw TException("Finding object error", (Error)rv);
    }

    vector<CK_OBJECT_HANDLE> result(lHandleCount);
    for(size_t i = 0; i < lHandleCount; i++)
        result[i] = pHandles[i];
    delete[] pHandles;
    rv = pFunctionList->C_FindObjectsFinal(hSession);
    return result;
}

void TKeyManager::overwriteAndFreeAttributes(CK_ATTRIBUTE_PTR attributes)
{
    if(attributes == nullptr)
        return;

    if(attributes[classPosition].pValue != nullptr)
    {
        CK_BYTE_PTR bpValue = (CK_BYTE_PTR)attributes[classPosition].pValue;
        for(size_t i = 0; i < attributes[classPosition].ulValueLen; i++)
            bpValue[i] = 0x00;
        delete[] attributes[classPosition].pValue;
    }
    if(attributes[keyTypePosition].pValue != nullptr)
    {
        CK_BYTE_PTR bpValue = (CK_BYTE_PTR)attributes[keyTypePosition].pValue;
        for(size_t i = 0; i < attributes[keyTypePosition].ulValueLen; i++)
            bpValue[i] = 0x00;
        delete[] attributes[keyTypePosition].pValue;
    }
    if(attributes[idPosition].pValue != nullptr)
    {
        CK_BYTE_PTR bpValue = (CK_BYTE_PTR)attributes[idPosition].pValue;
        for(size_t i = 0; i < attributes[idPosition].ulValueLen; i++)
            bpValue[i] = 0x00;
        delete[] attributes[idPosition].pValue;
    }
    if(attributes[labelPosition].pValue != nullptr)
    {
        CK_BYTE_PTR bpValue = (CK_BYTE_PTR)attributes[labelPosition].pValue;
        for(size_t i = 0; i < attributes[labelPosition].ulValueLen; i++)
            bpValue[i] = 0x00;
        delete[] attributes[labelPosition].pValue;
    }
}

void TKeyManager::overwriteAndFreeAttributesWithValue(CK_ATTRIBUTE_PTR attributes)
{
    if(attributes == nullptr)
        return;

    overwriteAndFreeAttributes(attributes);

    if(attributes[valuePosition].pValue != nullptr)
    {
        CK_BYTE_PTR bpValue = (CK_BYTE_PTR)attributes[valuePosition].pValue;
        for(size_t i = 0; i < attributes[valuePosition].ulValueLen; i++)
            bpValue[i] = 0x00;
        delete[] attributes[valuePosition].pValue;
    }

}

CK_ATTRIBUTE_PTR TKeyManager::getAttributeArray(const CK_OBJECT_CLASS objectClass, const CK_KEY_TYPE keyType, map<Attribute, string> attributes, int64_t *size)
{
    preCheck();
    if(!(objectClass != CKO_PRIVATE_KEY || objectClass != CKO_SECRET_KEY || objectClass != CKO_PUBLIC_KEY))
    {
        throw new TException("Unknown key class", Error::UNKNOWN_KEY_CLASS);
    }
    *size = 0;

    CK_OBJECT_CLASS *object_class = new CK_OBJECT_CLASS;
    *object_class = objectClass;
    CK_KEY_TYPE *key_type = new CK_KEY_TYPE;
    *key_type = keyType;

    bool *bToken = &bTrue;
    if(attributes[Attribute::TOKEN_] == "false")
        bToken = &bFalse;

    bool *bPrivate = objectClass == CKO_PUBLIC_KEY ? &bFalse : &bTrue;
    if(attributes[Attribute::PRIVATE] == "true")
        bPrivate = &bTrue;
    else if (attributes[Attribute::PRIVATE] == "false")
        bPrivate = &bFalse;

    bool *bModifialbe = &bTrue;
    if(attributes[Attribute::MODIFIABLE] == "false")
        bModifialbe = &bFalse;

    int64_t lIdSize = attributeIDSize;
    CK_BYTE_PTR bpID = nullptr;
    byte_array _keyID;
    if(attributes[Attribute::ID] == "")
    {
        bool done = false;
        do
        {
            bpID = generateId(&lIdSize);
            _keyID = session->GetTokenSerial();
            byte_array ba_tmp((byte*)bpID, (byte*)bpID + lIdSize);
            _keyID.insert(_keyID.end(), ba_tmp.begin(), ba_tmp.end());
            if(getKeyHandle(_keyID, objectClass).size() == 0)
            {
                done = true;
            }
            delete[] bpID;
            bpID = nullptr;
        }while(!done);
        bpID = PkcsConvert::ByteArray2CK_BYTE(_keyID, &lIdSize);
    }
    else
    {
        if(attributes[Attribute::ID].size() < 10)
        {
            _keyID = session->GetTokenSerial();
            _keyID.insert(_keyID.begin(), attributes[Attribute::ID].begin(), attributes[Attribute::ID].begin() + 2);
            if(getKeyHandle(_keyID, objectClass).size() > 0)
            {
                delete object_class;
                delete key_type;
                throw new TException("Same key id exists", Error::SAME_KEY_ID_EXISTS);
            }
        }
        else
        {
            _keyID = byte_array(attributes[Attribute::ID].begin(), attributes[Attribute::ID].end());
        }
        bpID = PkcsConvert::ByteArray2CK_BYTE(_keyID, &lIdSize);
    }

    int64_t lLabelSize = 0;
    CK_UTF8CHAR_PTR bpLabel = nullptr;
    if(attributes[Attribute::LABEL] == "")
    {
        switch(objectClass)
        {
        case CKO_PRIVATE_KEY:
            bpLabel = PkcsConvert::Str2CK_BYTE("Private key", &lLabelSize);
            break;
        case CKO_PUBLIC_KEY:
            bpLabel = PkcsConvert::Str2CK_BYTE("Public key", &lLabelSize);
            break;
        case CKO_SECRET_KEY:
            bpLabel = PkcsConvert::Str2CK_BYTE("Secret key", &lLabelSize);
            break;
        }
    }
    else
    {
        bpLabel = PkcsConvert::Str2CK_BYTE(attributes[Attribute::LABEL], &lLabelSize);
    }

    bool *bEncrypt = &bFalse;
    if(attributes[Attribute::ENCRYPT] == "true")
        bEncrypt = &bTrue;

    bool *bDecrypt = &bFalse;
    if(attributes[Attribute::DECRYPT] == "true")
        bDecrypt = &bTrue;

    bool *bSign = &bFalse;
    if(attributes[Attribute::SIGN] == "true")
        bSign = &bTrue;

    bool *bVerify = &bFalse;
    if(attributes[Attribute::VERIFY] == "true")
        bVerify = &bTrue;

    bool *bSensivite = &bTrue;
    if(attributes[Attribute::SENSITIVE] == "false")
        bSensivite = &bFalse;

    bool *bExctractible = &bFalse;
    if(attributes[Attribute::EXTRACTABLE] == "true")
        bExctractible = &bTrue;

    int64_t lValueSize = 0;
    CK_BYTE_PTR bpValue = nullptr;
    if(attributes[Attribute::VALUE] != "")
    {
        bpValue = PkcsConvert::Str2CK_BYTE(attributes[Attribute::VALUE], &lValueSize);
    }

    CK_ATTRIBUTE_PTR apAttributes = new CK_ATTRIBUTE[AttributesMaxCount];
    apAttributes[classPosition] = { CKA_CLASS, object_class, sizeof(*object_class) };
    apAttributes[keyTypePosition] = { CKA_KEY_TYPE, key_type, sizeof(*key_type) };
    apAttributes[idPosition] = { CKA_ID, bpID, (CK_ULONG)lIdSize };
    apAttributes[labelPosition] = { CKA_LABEL, bpLabel, (CK_ULONG)lLabelSize };
    size_t resultCount = 4;
    if(attributes[Attribute::VALUE] != "")
    {
        apAttributes[resultCount++] = { CKA_VALUE, bpValue, (CK_ULONG)lValueSize };
    }

    apAttributes[resultCount++] = { CKA_TOKEN, bToken, sizeof(*bToken) };
    apAttributes[resultCount++] = { CKA_PRIVATE, bPrivate, sizeof(*bPrivate) };
    apAttributes[resultCount++] = { CKA_MODIFIABLE, bModifialbe, sizeof(*bModifialbe) };

    switch(objectClass)
    {
    case CKO_PRIVATE_KEY:
        apAttributes[resultCount++] = { CKA_DECRYPT, bDecrypt, sizeof(*bDecrypt) };
        apAttributes[resultCount++] = { CKA_SIGN, bSign, sizeof(*bSign) };
        apAttributes[resultCount++] = { CKA_SENSITIVE, bSensivite, sizeof(*bSensivite) };
        apAttributes[resultCount++] = { CKA_EXTRACTABLE, bExctractible, sizeof(*bExctractible) };
        apAttributes[resultCount++] = { CKA_GOSTR3411_PARAMS, GOST3411_params_oid, sizeof(GOST3411_params_oid) };
        apAttributes[resultCount++] = { CKA_GOSTR3410_PARAMS, GOST3410_params_oid, sizeof(GOST3410_params_oid) };
        break;
    case CKO_PUBLIC_KEY:
        apAttributes[resultCount++] = { CKA_ENCRYPT, bEncrypt, sizeof(*bEncrypt) };
        apAttributes[resultCount++] = { CKA_VERIFY, bVerify, sizeof(*bVerify) };
        apAttributes[resultCount++] = { CKA_GOSTR3411_PARAMS, GOST3411_params_oid, sizeof(GOST3411_params_oid) };
        apAttributes[resultCount++] = { CKA_GOSTR3410_PARAMS, GOST3410_params_oid, sizeof(GOST3410_params_oid) };
        break;
    case CKO_SECRET_KEY:
        apAttributes[resultCount++] = { CKA_ENCRYPT, bEncrypt, sizeof(*bEncrypt) };
        apAttributes[resultCount++] = { CKA_DECRYPT, bDecrypt, sizeof(*bDecrypt) };
        apAttributes[resultCount++] = { CKA_SIGN, bSign, sizeof(*bSign) };
        apAttributes[resultCount++] = { CKA_VERIFY, bVerify, sizeof(*bVerify) };
        apAttributes[resultCount++] = { CKA_SENSITIVE, bSensivite, sizeof(*bSensivite) };
        apAttributes[resultCount++] = { CKA_EXTRACTABLE, bExctractible, sizeof(*bExctractible) };
        apAttributes[resultCount++] = { CKA_GOST28147_PARAMS, GOST28147_params_oid, sizeof(GOST28147_params_oid) };
        break;
    }
    *size = resultCount;

    return apAttributes;
}

CK_BYTE_PTR TKeyManager::generateId(int64_t *size)
{
    CK_BYTE_PTR result = nullptr;

    if(*size == 0)
        *size = 8;
    result = new CK_BYTE[*size];
    for(size_t i = 0; i < *size; i++)
    {
        result[i] = (CK_BYTE)(rand() % 0x100);
    }
    return result;
}

byte_array TKeyManager::GenerateKeyGOST28147(map<Attribute, string> &attributes)
{
    preCheck();

    CK_MECHANISM gost28147_mech = { CKM_GOST28147_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE secretKeyHandle = NULL_PTR;

    int64_t lAttributesSize = 0;
    CK_ATTRIBUTE_PTR attrGost28147_Secret = getAttributeArray(CKO_SECRET_KEY, CKK_GOST28147, attributes, &lAttributesSize);
    CK_RV rv = pFunctionList->C_GenerateKey(hSession, &gost28147_mech, attrGost28147_Secret, lAttributesSize, &secretKeyHandle);
    CK_BYTE_PTR bpID = (CK_BYTE_PTR)attrGost28147_Secret[idPosition].pValue;
    CK_ULONG ulIDSize = attrGost28147_Secret[idPosition].ulValueLen;
    byte_array returnedID((byte*)bpID, (byte*)bpID + ulIDSize);
    overwriteAndFreeAttributesWithValue(attrGost28147_Secret);

    if(rv != CKR_OK)
    {
        throw new TException("Can't generate secret key", (Error)rv);
    }

    return returnedID;
}

vector<map<Attribute, string>> TKeyManager::GetSecretKeyList()
{
    return getKeyList(CKO_SECRET_KEY);
}

bool TKeyManager::IsSecretKeyExists(const byte_array &keyID)
{
    return getKeyHandle(keyID, CKO_SECRET_KEY).size() > 0;
}

void TKeyManager::RemoveSecretKey(const byte_array &keyID)
{
    removeKey(keyID, CKO_SECRET_KEY);
}

void TKeyManager::RemoveAllKeys()
{
    preCheck();

    vector<CK_OBJECT_HANDLE> handles = findKeys(CKO_PRIVATE_KEY);
    vector<CK_OBJECT_HANDLE> tmp = findKeys(CKO_PUBLIC_KEY);
    handles.insert(handles.end(), tmp.begin(), tmp.end());
    tmp = findKeys(CKO_SECRET_KEY);
    handles.insert(handles.end(), tmp.begin(), tmp.end());

    for(auto &i: handles)
    {
        CK_RV rv = pFunctionList->C_DestroyObject(hSession, i);
    }
}

void TKeyManager::FreeAttributesTemplate(map<Attribute, string> *attributeTmpl)
{
}

vector<CK_OBJECT_HANDLE> TKeyManager::findKeys(const CK_OBJECT_CLASS objectClass)
{
    preCheck();

    CK_RV rv = CKR_OK;
    vector<CK_OBJECT_HANDLE> result;
    CK_OBJECT_CLASS ocKey = objectClass;
    CK_ATTRIBUTE keySearchForClassAttr[] = { CKA_CLASS, &ocKey, sizeof(ocKey) };
    rv = pFunctionList->C_FindObjectsInit(hSession, keySearchForClassAttr, arraysize(keySearchForClassAttr));
    if(rv != CKR_OK)
    {
        throw new TException("Can't initialize search operation", (Error)rv);
    }

    CK_OBJECT_HANDLE_PTR opHandles = new CK_OBJECT_HANDLE[64];
    memset(opHandles, 0x00, 64 * sizeof(CK_OBJECT_HANDLE));

    CK_ULONG ulHandlesCount = 0;
    rv = pFunctionList->C_FindObjects(hSession, opHandles, 65, &ulHandlesCount);
    if(rv != CKR_OK)
    {
        rv = pFunctionList->C_FindObjectsFinal(hSession);
        delete[] opHandles;
        throw new TException("Can't find objects", (Error)rv);
    }

    for(size_t i = 0; i < ulHandlesCount; i++)
        result.push_back(opHandles[i]);
    delete[] opHandles;
    rv = pFunctionList->C_FindObjectsFinal(hSession);

    return result;
}

vector<map<Attribute, string>> TKeyManager::getKeyList(const CK_OBJECT_CLASS objectClass)
{
    preCheck();

    vector<map<Attribute, string>> result;
    CK_RV rv = CKR_OK;
    vector<CK_OBJECT_HANDLE> handles = findKeys(objectClass);
    for(auto &i: handles)
    {
        CK_ATTRIBUTE gettingValueAttr[] =
        {
            { CKA_LABEL, NULL_PTR, 0 },
            { CKA_ID, NULL_PTR, 0 }
        };
        rv = pFunctionList->C_GetAttributeValue(hSession, i, gettingValueAttr, arraysize(gettingValueAttr));
        if(rv != CKR_OK)
            continue;

        gettingValueAttr[0].pValue = new CK_UTF8CHAR[gettingValueAttr[0].ulValueLen];
        gettingValueAttr[1].pValue = new CK_UTF8CHAR[gettingValueAttr[1].ulValueLen];
        rv = pFunctionList->C_GetAttributeValue(hSession, i, gettingValueAttr, arraysize(gettingValueAttr));
        if(rv != CKR_OK)
        {
            delete[] (CK_BYTE_PTR)gettingValueAttr[0].pValue;
            delete[] (CK_BYTE_PTR)gettingValueAttr[1].pValue;
            continue;
        }
        string label = string((const char*)gettingValueAttr[0].pValue, gettingValueAttr[0].ulValueLen);
        string id = string((const char*)gettingValueAttr[1].pValue, gettingValueAttr[1].ulValueLen);
        map<Attribute, string> mTmp;
        mTmp.insert(std::pair<Attribute, string>(Attribute::LABEL, label));
        mTmp.insert(std::pair<Attribute, string>(Attribute::ID, id));
        result.push_back(mTmp);
        delete[] (CK_BYTE_PTR)gettingValueAttr[0].pValue;
        delete[] (CK_BYTE_PTR)gettingValueAttr[1].pValue;
        mTmp.clear();
    }

    return result;
}

void TKeyManager::removeKey(const byte_array &keyID, const CK_OBJECT_CLASS objectClass)
{
    preCheck();
    vector<CK_OBJECT_HANDLE> handles = getKeyHandle(keyID, objectClass);
    for(auto &i: handles)
    {
        pFunctionList->C_DestroyObject(hSession, i);
    }
}
