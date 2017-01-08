#include <iostream>
#include <vector>
#include <map>

#include "rtpkcs11ecplib.h"
#include "tokensession.h"
#include "tokenservant.h"
#include "pkcs_types.h"
#include "texception.h"
#include "tcryptomanager.h"

#include "tkeysmanager.h"

using namespace std;

#define deleteIfNotNull(a) if(a != nullptr) delete a

#ifndef __BYTE_ARRAY__
#define __BYTE_ARRAY__
typedef std::vector<unsigned char> ByteArray;
#endif


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

    string keyID = "";
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
        keyID = sKeyList[0][Attribute::ID];
        cout << "Keys printed" << endl;
    }
    catch(TException *te)
    {
        cout << te->GetReason() << " " << (int64_t)te->GetCode() << endl;
        delete te;
    }

    cout << "KeyID size: " << keyID << endl;
    cout << "KeyID: " << keyID << endl;

    /* DIGEST TESTING */
    try
    {
        string plaintext = "Plaintext for hash";
        cout << "Plaintext: " << plaintext << endl;

        string digest_94 = crypto->Digest_Gost3411_94(plaintext);
        cout << "\tDigest 94 size: " << digest_94.size() << endl;
        cout << "\tDigest 94: " << digest_94 << endl;
        if(crypto->IsValidDigest_Gost3411_94(plaintext, digest_94)) cout << "\tDigest is valid" << endl;
        else cout << "\tDigest is invalid" << endl;

        string digest_12_256 = crypto->Digest_Gost3411_12_256(plaintext);
        cout << "\tDigest 2012 256 size: " << digest_12_256.size() << endl;
        cout << "\tDigest 2012 256: " << digest_12_256 << endl;
        if(crypto->IsValidDigest_Gost3411_12_256(plaintext, digest_12_256)) cout << "\tDigest is valid" << endl;
        else cout << "\tDigest is invalid" << endl;

        string digest_12_512 = crypto->Digest_Gost3411_12_512(plaintext);
        cout << "\tDigest 2012 512 size: " << digest_12_512.size() << endl;
        cout << "\tDigest 2012 512: " << digest_12_512 << endl;
        if(crypto->IsValidDigest_Gost3411_12_512(plaintext, digest_12_512)) cout << "\tDigest is valid" << endl;
        else cout << "\tDigest is invalid" << endl;

        int randomSize = 8;
        string random = crypto->GetRandom(randomSize);
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
        string plaintext = "Plaintext for enc/dec";
        string iv = "initvect";
        cout << "\tPlaintext size: " << plaintext.size() << endl;
        cout << "\tPlaintext: " << plaintext << endl;
        cout << "\tIV size: " << iv.size() << endl;
        cout << "\tIV: " << iv << endl;
        cout << endl;

        string ciphertext = crypto->Encrypt_Gost28147(keyID, plaintext, &iv);
        cout << "\tCiphertext size: " << ciphertext.size() << endl;
        cout << "\tCiphertext" << ciphertext << endl;
        cout << endl;

        string _plaintext = crypto->Decrypt_Gost28147(keyID, ciphertext, &iv);
        cout << "\tDeciphered size: " << _plaintext.size() << endl;
        cout << "\tDeciphered: " << _plaintext << endl;

        if(plaintext == _plaintext) cout << "\tPlaintexts are equals" << endl;
        else cout << "\tPlaintexts aren't equals" << endl;
        cout << endl;

        /* GOST 28147-89 ECB TESTING */
        cout << "GOST 28147-89 ECB TESTING" << endl;
        string plaintextEcb(plaintext);
        string cTextEcb = crypto->Encrypt_Gost28147_ECB(keyID, plaintextEcb);
        cout << "\tChanged plaintext: " << plaintextEcb << endl;
        cout << "\tCiphertext size: " << cTextEcb.size() << endl;
        cout << cTextEcb << endl;

        string dTextEcb = crypto->Decrypt_Gost28147_ECB(keyID, cTextEcb);
        cout << "\tDeciphered size: " << dTextEcb.size() << endl;
        cout << "\tDiciphered: " << dTextEcb << endl;

        if(dTextEcb.substr(0, plaintext.size()) == plaintext) cout << "\tPlaintexts are equals" << endl;
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
        string plaintext = "Plaintext for MAC";
        string iv = "initvect";
        cout << "Plaintext size: " << plaintext.size() << endl;
        cout << "Plaintext: " << plaintext << endl;
        cout << "\tIV size: " << iv.size() << endl;
        cout << "\tIV: " << iv << endl;

        string signature = crypto->MAC_Gost28147_SIGN(keyID, plaintext, iv);
        cout << "\tSignature size: " << signature.size() << endl;
        cout << "\tSignature: " << signature << endl;

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
