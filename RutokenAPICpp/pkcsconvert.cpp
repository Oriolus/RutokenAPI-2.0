#include "pkcsconvert.h"

PkcsConvert::PkcsConvert()
{

}

string PkcsConvert::Bool2Str(const bool value)
{
    return value ? string("true") : string("false");
}

bool PkcsConvert::Str2Bool(const string value)
{
    return value == string("true");
}

CK_BYTE_PTR PkcsConvert::Str2CK_BYTE(const string &in_str, int64_t *outsize)
{
    if(outsize == nullptr)
        return nullptr;
    *outsize = in_str.size();
    CK_BYTE_PTR result = new CK_BYTE[*outsize];
    memcpy_s(result, *outsize, in_str.data(), *outsize);
    return result;
}

CK_BYTE_PTR PkcsConvert::Str2CK_BYTE(const char *in_str, int64_t *outsize)
{
    string tmp = string(in_str);
    return PkcsConvert::Str2CK_BYTE(tmp, outsize);
}

void PkcsConvert::OverwriteStr(string *str)
{
    string tmp = string(str->size(), (char)0x00);
    str->replace(str->begin(), str->end(), tmp.begin(), tmp.end());
}

string PkcsConvert::Trim(std::string &str)
{
    size_t first = str.find_first_not_of(' ');
    if (string::npos == first)
    {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}
