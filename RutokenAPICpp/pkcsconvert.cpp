#include "pkcsconvert.h"

pkcs11_core::PkcsConvert::PkcsConvert()
{

}

std::string pkcs11_core::PkcsConvert::Bool2Str(const bool value)
{
    return value ? std::string("true") : std::string("false");
}

bool pkcs11_core::PkcsConvert::Str2Bool(const std::string value)
{
    return value == std::string("true");
}

CK_BYTE_PTR pkcs11_core::PkcsConvert::Str2CK_BYTE(const std::string &in_str, int64_t *outsize)
{
    if(outsize == nullptr)
        return nullptr;
    *outsize = in_str.size();
    CK_BYTE_PTR result = new CK_BYTE[*outsize];
    memcpy_s(result, *outsize, in_str.data(), *outsize);
    return result;
}

CK_BYTE_PTR pkcs11_core::PkcsConvert::Str2CK_BYTE(const char *in_str, int64_t *outsize)
{
    std::string tmp = std::string(in_str);
    return PkcsConvert::Str2CK_BYTE(tmp, outsize);
}

void pkcs11_core::PkcsConvert::OverwriteStr(std::string *str)
{
    std::string tmp = std::string(str->size(), (char)0x00);
    str->replace(str->begin(), str->end(), tmp.begin(), tmp.end());
}

std::string pkcs11_core::PkcsConvert::Trim(std::string &str)
{
    size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first)
    {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

void pkcs11_core::PkcsConvert::OverwriteByteArray(byte_array *ba)
{
    unsigned char *ba_data = (unsigned char*)ba->data();
    for(size_t i = 0; i < ba->size(); i++)
        ba_data[i] = 0x00;
}

CK_BYTE_PTR pkcs11_core::PkcsConvert::ByteArray2CK_BYTE(const byte_array &ba, int64_t *outsize)
{
    *outsize = 0;
    CK_BYTE_PTR result = new CK_BYTE[ba.size()];
    for(size_t i = 0; i < ba.size(); i++)
        result[i] = ba[i];
    *outsize = ba.size();
    return result;
}

byte_array pkcs11_core::PkcsConvert::TrimBA(byte_array &ba)
{
    int space_q = 0;
    for(; ba[ba.size() - 1 - space_q] == ' '; space_q++);
    if(space_q == 0) return ba;
    return byte_array(ba.begin(), ba.end() - space_q);
}
