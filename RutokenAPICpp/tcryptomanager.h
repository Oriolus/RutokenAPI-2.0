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

#ifndef __BYTE_ARRAY__
#define __BYTE_ARRAY__
typedef vector<byte> byte_array;
#endif

namespace pkcs11_core
{

#ifndef __BYTE_ARRAY__
#define __BYTE_ARRAY__
typedef std::vector<byte> byte_array;
#endif

namespace crypto
{

class TKeyManager;

class TCryptoManager
{
public:
    TCryptoManager(device::TokenSession *tSession, TKeyManager *keyManager);
    ~TCryptoManager();

    byte_array              GetRandom(const int32_t size);

    byte_array              Digest_Gost3411_94(const byte_array &plaintext);
    byte_array              Digest_Gost3411_12_256(const byte_array &plaintext);
    byte_array              Digest_Gost3411_12_512(const byte_array &plaintext);

    bool                    IsValidDigest_Gost3411_94(const byte_array &plaintext, const byte_array digest);
    bool                    IsValidDigest_Gost3411_12_256(const byte_array &plaintext, const byte_array digest);
    bool                    IsValidDigest_Gost3411_12_512(const byte_array &plaintext, const byte_array digest);

    byte_array              Encrypt_Gost28147(const byte_array &keyID, const byte_array &plaintext, const byte_array *IV);
    byte_array              Decrypt_Gost28147(const byte_array &keyID, const byte_array &ciphertext, const byte_array *IV);

    byte_array              Encrypt_Gost28147_ECB(const byte_array &keyID, byte_array &plaintext);
    byte_array              Decrypt_Gost28147_ECB(const byte_array &keyID, const byte_array &ciphertext);

    byte_array              MAC_Gost28147_SIGN(const byte_array &keyID, const byte_array &plaintext, const byte_array &IV);
    bool                    MAC_Gost28147_VERIFY(const byte_array &keyID, const byte_array &plaintext, const byte_array &IV, const byte_array &signature);

    void                    SetSessionHandle(const uint64_t hSession) { this->hSession = (CK_SESSION_HANDLE)hSession; }

private:
    device::TokenSession    *tSession;
    TKeyManager             *keyManager;
    CK_SESSION_HANDLE       hSession;
    CK_FUNCTION_LIST_PTR    pFunctionList;

    void                    preCheck();
    CK_BYTE_PTR             getRandom(const int32_t size);

    CK_BYTE_PTR             encrypt(const CK_OBJECT_HANDLE hKey, const CK_BYTE_PTR bpPlaintext, const CK_ULONG lPlaintextSize, const CK_BYTE_PTR bpIV, const CK_ULONG lIVSize, uint64_t *lCiphertextSize, const CK_MECHANISM_TYPE encMechType);
    byte_array              sEncrypt(const byte_array &keyID, const byte_array &plaintext, const byte_array *IV, const CK_MECHANISM_TYPE encMechType, const CK_OBJECT_CLASS keyClass);

    CK_BYTE_PTR             decrypt(const CK_OBJECT_HANDLE hKey, const CK_BYTE_PTR bpCiphertext, const CK_ULONG lCiphertextSize, const CK_BYTE_PTR bpIV, const CK_ULONG lIVSize, uint64_t *lPlaintextSize, const CK_MECHANISM_TYPE decMechType);
    byte_array              sDecrypt(const byte_array &keyID, const byte_array &ciphertext, const byte_array *IV, const CK_MECHANISM_TYPE decMechType, const CK_OBJECT_CLASS keyClass);

    CK_BYTE_PTR             digest(const CK_BYTE_PTR bpPlaintext, const uint64_t lPlaintextSize, uint64_t *lDigestSize, const CK_MECHANISM_TYPE digestMech);
    byte_array              sDigest(const byte_array &plaintext, const uint64_t lDigestSize, const CK_MECHANISM_TYPE digestMech);

    CK_BYTE_PTR             mac(const CK_OBJECT_HANDLE hKey, const CK_BYTE_PTR bpPlaintext, const CK_ULONG lPlaintextSize, const CK_BYTE_PTR bpIV, const CK_ULONG lIVSize, const uint64_t lMacSize, const CK_MECHANISM_TYPE macMechType);
    byte_array              sMac(const byte_array &keyID, const byte_array &plaintext, const byte_array *IV, const uint64_t lMacSize, const CK_MECHANISM_TYPE macMechType, const CK_OBJECT_CLASS keyClass);

    bool                    verify(const CK_OBJECT_HANDLE hKey, const CK_BYTE_PTR bpPlaintext, const CK_ULONG lPlaintextSize, const CK_BYTE_PTR bpIV, const CK_ULONG lIVSize, const CK_BYTE_PTR bpSignature, const CK_ULONG lSignatureSize, const CK_MECHANISM_TYPE verMechType);
    bool                    isSignatureCorrect(const byte_array &keyID, const byte_array &plaintext, const byte_array *IV, const byte_array &signature, const CK_MECHANISM_TYPE verMechType, const CK_OBJECT_CLASS keyClass);

};

}
}




#endif // TCRYPTOMANAGER_H
