#ifndef TCRYPTOMANAGER_H
#define TCRYPTOMANAGER_H

#include "Common.h"
#include "enums.h"
#include "tokensession.h"
#include "texception.h"
#include "pkcsconvert.h"
#include "tkeysmanager.h"

#include <string>
#include <vector>
#include <cstdlib>

class TKeyManager;

using std::string;
using std::vector;

class TCryptoManager
{
public:
    TCryptoManager(TokenSession *tSession, TKeyManager *keyManager);

    string                  GetRandom(const int32_t size);

    string                  Digest_Gost3411_94(const string &plaintext);
    string                  Digest_Gost3411_12_256(const string &plaintext);
    string                  Digest_Gost3411_12_512(const string &plaintext);

    bool                    IsValidDigest_Gost3411_94(const string &plaintext, const string digest);
    bool                    IsValidDigest_Gost3411_12_256(const string &plaintext, const string digest);
    bool                    IsValidDigest_Gost3411_12_512(const string &plaintext, const string digest);

    string                  Encrypt_Gost28147(const string &keyID, const string &plaintext, const string *IV);
    string                  Decrypt_Gost28147(const string &keyID, const string &ciphertext, const std::string *IV);
    string                  MAC_Gost28147_SIGN(const string &keyID, const string &plaintext, const string &IV);
    bool                    MAC_Gost28147_VERIFY(const string &keyID, const string &plaintext, const string &IV, const string &signature);

    void                    SetSessionHandle(const uint64_t hSession) { this->hSession = (CK_SESSION_HANDLE)hSession; }

private:
    TokenSession            *tSession;
    TKeyManager             *keyManager;
    CK_SESSION_HANDLE       hSession;
    CK_FUNCTION_LIST_PTR    pFunctionList;

    void                    preCheck();
    CK_BYTE_PTR             getRandom(const int32_t size);

    CK_BYTE_PTR             encrypt(const CK_OBJECT_HANDLE hKey, const CK_BYTE_PTR bpPlaintext, const CK_ULONG lPlaintextSize, const CK_BYTE_PTR bpIV, const CK_ULONG lIVSize, uint64_t *lCiphertextSize, const CK_MECHANISM_TYPE encMechType);
    string                  sEncrypt(const string &keyID, const string &plaintext, const string *IV, const CK_MECHANISM_TYPE encMechType, const CK_OBJECT_CLASS keyClass);

    CK_BYTE_PTR             decrypt(const CK_OBJECT_HANDLE hKey, const CK_BYTE_PTR bpCiphertext, const CK_ULONG lCiphertextSize, const CK_BYTE_PTR bpIV, const CK_ULONG lIVSize, uint64_t *lPlaintextSize, const CK_MECHANISM_TYPE decMechType);
    string                  sDecrypt(const string &keyID, const string &ciphertext, const string *IV, const CK_MECHANISM_TYPE decMechType, const CK_OBJECT_CLASS keyClass);

    CK_BYTE_PTR             digest(const CK_BYTE_PTR bpPlaintext, const uint64_t lPlaintextSize, uint64_t *lDigestSize, const CK_MECHANISM_TYPE digestMech);
    string                  sDigest(const string &plaintext, const uint64_t lDigestSize, const CK_MECHANISM_TYPE digestMech);

    CK_BYTE_PTR             mac(const CK_OBJECT_HANDLE hKey, const CK_BYTE_PTR bpPlaintext, const CK_ULONG lPlaintextSize, const CK_BYTE_PTR bpIV, const CK_ULONG lIVSize, const uint64_t lMacSize, const CK_MECHANISM_TYPE macMechType);
    string                  sMac(const string &keyID, const string &plaintext, const string *IV, const uint64_t lMacSize, const CK_MECHANISM_TYPE macMechType, const CK_OBJECT_CLASS keyClass);

    bool                   verify(const CK_OBJECT_HANDLE hKey, const CK_BYTE_PTR bpPlaintext, const CK_ULONG lPlaintextSize, const CK_BYTE_PTR bpIV, const CK_ULONG lIVSize, const CK_BYTE_PTR bpSignature, const CK_ULONG lSignatureSize, const CK_MECHANISM_TYPE verMechType);
    bool                   isSignatureCorrect(const string &keyID, const string &plaintext, const string *IV, const string &signature, const CK_MECHANISM_TYPE verMechType, const CK_OBJECT_CLASS keyClass);

};

#endif // TCRYPTOMANAGER_H
