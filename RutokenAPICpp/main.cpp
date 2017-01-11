#include <iostream>
#include <vector>
#include <map>

#include "pkcs11_core.h"

using namespace std;

using namespace pkcs11_core;
using namespace pkcs11_core::lib;
using namespace pkcs11_core::device;
using namespace pkcs11_core::crypto;

#define deleteIfNotNull(a) if(a != nullptr) delete a

int main(int argc, char *argv[])
{
    RtPKCS11EcpLib *lib = nullptr;
    TokenSession *ts = nullptr;
    TokenServant *tServ = nullptr;
    TKeyManager *keys = nullptr;
    TCryptoManager *crypto = nullptr;
    try
    {
        lib = new RtPKCS11EcpLib();
        ts = new TokenSession(lib->GetFunctionListPtr(), lib->GetExFunctionListPtr());
        tServ = new TokenServant(lib->GetFunctionListPtr(), lib->GetExFunctionListPtr());
        keys = new TKeyManager(ts);
        crypto = new TCryptoManager(ts, keys);
        cout << "Objects created" << endl;
    }
    catch(TException *te)
    {
        deleteIfNotNull(crypto);
        deleteIfNotNull(keys);
        deleteIfNotNull(ts);
        deleteIfNotNull(tServ);
        deleteIfNotNull(lib);
        cout << te->GetReason() << endl;
        delete te;
    }

    vector<TokenInfo> tInfo;
    try
    {
        if(tServ != nullptr)
            tInfo= tServ->GetTokenList();
        for(TokenInfo &ti: tInfo)
        {
            cout << ti.Label << " " << ti.Serial << endl;
        }
    }
    catch(TException *te)
    {
        cout << te->GetReason() << endl;
        delete te;
    }

    try
    {
        if(tInfo.size() > 0)
        {
            ts->OpenSessionOnSlot(tInfo[0].Slot);
            string pin = string("12345678");
            ts->Login((int64_t)User::USER, pin);
            keys->SetSessionHandle(ts->GetSessionHandle());
            crypto->SetSessionHandle(ts->GetSessionHandle());
            cout << "Succesfull loged in" << endl;
        }
    }
    catch(TException *te)
    {
        cout << te->GetReason() << " " << (int64_t)te->GetCode() << endl;
        delete te;
    }

    byte_array keyID;
    try
    {
        map<Attribute, string> secKeyTmpl;
        //secKeyTmpl.insert(std::pair<Attribute, string>(Attribute::TOKEN_, "false"));
        secKeyTmpl.insert(std::pair<Attribute, string>(Attribute::DECRYPT, "true"));
        secKeyTmpl.insert(std::pair<Attribute, string>(Attribute::ENCRYPT, "true"));
        secKeyTmpl.insert(std::pair<Attribute, string>(Attribute::SIGN, "true"));
        secKeyTmpl.insert(std::pair<Attribute, string>(Attribute::VERIFY, "true"));
        //keyID = keys->CreateSecretKey(secKeyTmpl);
        //cout << keyID << endl;
        vector<map<Attribute, string>> sKeyList = keys->GetSecretKeyList();
        for(auto &mKeys: sKeyList)
        {
            cout << mKeys[Attribute::ID] << endl;
            cout << mKeys[Attribute::LABEL] << endl;
            cout << endl;
        }
        keyID = byte_array(sKeyList[0][Attribute::ID].begin(), sKeyList[0][Attribute::ID].end());
        cout << "Keys printed" << endl;
    }
    catch(TException *te)
    {
        cout << te->GetReason() << " " << (int64_t)te->GetCode() << endl;
        delete te;
    }

    cout << "KeyID size: " << keyID.size() << endl;
    cout << "KeyID: " << string(keyID.begin(), keyID.end()) << endl;

    /* DIGEST TESTING */
    try
    {
        cout << "DIGEST TESTING" << endl;
        string sPlaintext = "Plaintext for hash";
        cout << "\tPlaintext: " << sPlaintext << endl;
        byte_array plaintext(sPlaintext.begin(), sPlaintext.end());

        byte_array digest_94 = crypto->Digest_Gost3411_94(plaintext);
        cout << "\tDigest 94 size: " << digest_94.size() << endl;
        cout << "\tDigest 94: " << string(digest_94.begin(), digest_94.end()) << endl;
        if(crypto->IsValidDigest_Gost3411_94(plaintext, digest_94)) cout << "\tDigest is valid" << endl;
        else cout << "\tDigest is invalid" << endl;
        cout << endl;

        byte_array digest_12_256 = crypto->Digest_Gost3411_12_256(plaintext);
        cout << "\tDigest 2012 256 size: " << digest_12_256.size() << endl;
        cout << "\tDigest 2012 256: " << string(digest_12_256.begin(), digest_12_256.end()) << endl;
        if(crypto->IsValidDigest_Gost3411_12_256(plaintext, digest_12_256)) cout << "\tDigest is valid" << endl;
        else cout << "\tDigest is invalid" << endl;
        cout << endl;

        byte_array digest_12_512 = crypto->Digest_Gost3411_12_512(plaintext);
        cout << "\tDigest 2012 512 size: " << digest_12_512.size() << endl;
        cout << "\tDigest 2012 512: " << string(digest_12_512.begin(), digest_12_512.end()) << endl;
        if(crypto->IsValidDigest_Gost3411_12_512(plaintext, digest_12_512)) cout << "\tDigest is valid" << endl;
        else cout << "\tDigest is invalid" << endl;
        cout << endl;

        int randomSize = 8;
        byte_array random = crypto->GetRandom(randomSize);
        int8_t *tmp = (int8_t*)random.data();
        for(size_t i = 0; i < randomSize; i++)
            cout << (int)tmp[i] << " ";
        cout << endl;
    }
    catch(TException *te)
    {
        cout << te->GetReason() << " " << (int64_t)te->GetCode() << endl;
        delete te;
    }

    /* ENCRYPT/DECRYPT TESTING */

    cout << endl;
    try
    {
        cout << "GOST 28147-89 CBC TESTING" << endl;
        string sPlaintext = "Plaintext for enc/dec";
        string sIv = "initvect";
        cout << "\tPlaintext size: " << sPlaintext.size() << endl;
        cout << "\tPlaintext: " << sPlaintext << endl;
        cout << "\tIV size: " << sIv.size() << endl;
        cout << "\tIV: " << sIv << endl;
        cout << endl;

        byte_array plaintext(sPlaintext.begin(), sPlaintext.end());
        byte_array iv(sIv.begin(), sIv.end());
        byte_array ciphertext = crypto->Encrypt_Gost28147(keyID, plaintext, &iv);
        cout << "\tCiphertext size: " << ciphertext.size() << endl;
        cout << "\tCiphertext" << string(ciphertext.begin(), ciphertext.end()) << endl;
        cout << endl;

        byte_array _plaintext = crypto->Decrypt_Gost28147(keyID, ciphertext, &iv);
        cout << "\tDeciphered size: " << _plaintext.size() << endl;
        cout << "\tDeciphered: " << string(_plaintext.begin(), _plaintext.end()) << endl;

        if(plaintext == _plaintext) cout << "\tPlaintexts are equals" << endl;
        else cout << "\tPlaintexts aren't equals" << endl;
        cout << endl;

        /* GOST 28147-89 ECB TESTING */
        cout << "GOST 28147-89 ECB TESTING" << endl;
        byte_array plaintextEcb(plaintext);
        byte_array cTextEcb = crypto->Encrypt_Gost28147_ECB(keyID, plaintextEcb);
        cout << "\tChanged plaintext: " << string(plaintextEcb.begin(), plaintextEcb.end()) << endl;
        cout << "\tCiphertext size: " << cTextEcb.size() << endl;
        cout << string(cTextEcb.begin(), cTextEcb.end()) << endl;

        byte_array dTextEcb = crypto->Decrypt_Gost28147_ECB(keyID, cTextEcb);
        cout << "\tDeciphered size: " << dTextEcb.size() << endl;
        cout << "\tDiciphered: " << string(dTextEcb.begin(), dTextEcb.end()) << endl;

        if(byte_array(dTextEcb.begin(), dTextEcb.begin() + plaintext.size()) == plaintext) cout << "\tPlaintexts are equals" << endl;
        else cout << "\tPlaintexts aren't equals" << endl;
        cout << endl;

    }
    catch(TException *te)
    {
        cout << te->GetReason() << " " << (int64_t)te->GetCode() << endl;
        cout << endl;
        delete te;
    }

    /* MAC TESTING */
    try
    {
        cout << "GOST 28147-89 MAC TESTING" << endl;
        string sPlaintext = "Plaintext for MAC";
        string sIv = "initvect";
        cout << "Plaintext size: " << sPlaintext.size() << endl;
        cout << "Plaintext: " << sPlaintext << endl;
        cout << "\tIV size: " << sIv.size() << endl;
        cout << "\tIV: " << sIv << endl;

        byte_array plaintext(sPlaintext.begin(), sPlaintext.end());
        byte_array iv(sIv.begin(), sIv.end());
        byte_array signature = crypto->MAC_Gost28147_SIGN(keyID, plaintext, iv);
        cout << "\tSignature size: " << signature.size() << endl;
        cout << "\tSignature: " << string(signature.begin(), signature.end()) << endl;

        if(crypto->MAC_Gost28147_VERIFY(keyID, plaintext, iv, signature))
            cout << "\tSignature is correct" << endl;
        else
            cout << "\tSignature isn't correct" << endl;
    }
    catch(TException *te)
    {
        cout << te->GetReason() << " " << (int64_t)te->GetCode() << endl;
        delete te;
    }

    deleteIfNotNull(crypto);
    deleteIfNotNull(keys);
    deleteIfNotNull(ts);
    deleteIfNotNull(tServ);
    deleteIfNotNull(lib);

    cout << "Ending" << endl;
    return 0;
}
