#ifndef PKCSCONVERT_H
#define PKCSCONVERT_H

#include <string>
#include <cstdlib>
#include "Common.h"

namespace pkcs11_core
{

class PkcsConvert
{
public:
    static std::string  Bool2Str(const bool value);
    static bool         Str2Bool(const std::string value);
    static CK_BYTE_PTR  Str2CK_BYTE(const std::string &in_str, int64_t *outsize);
    static CK_BYTE_PTR  Str2CK_BYTE(const char *in_str, int64_t *outsize);
    static void         OverwriteStr(std::string *str);

    static void         OverwriteByteArray(byte_array *ba);
    static CK_BYTE_PTR  ByteArray2CK_BYTE(const byte_array &ba, int64_t *outsize);
    static byte_array   TrimBA(byte_array &ba);

    static std::string  Trim(std::string &str);
private:
    PkcsConvert();
};

} // pkcs11_core

#endif // PKCSCONVERT_H
