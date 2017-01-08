#ifndef PKCSCONVERT_H
#define PKCSCONVERT_H

#include <string>
#include <cstdlib>
#include "Common.h"

using std::string;

class PkcsConvert
{
public:
    static string       Bool2Str(const bool value);
    static bool         Str2Bool(const string value);
    static CK_BYTE_PTR  Str2CK_BYTE(const string &in_str, int64_t *outsize);
    static CK_BYTE_PTR  Str2CK_BYTE(const char *in_str, int64_t *outsize);
    static void         OverwriteStr(string *str);

    static void         OverwriteByteArray(byte_array *ba);
    static CK_BYTE_PTR  ByteArray2CK_BYTE(const byte_array &ba, int64_t *outsize);
    static byte_array   TrimBA(byte_array &ba);

    static string       Trim(string &str);
private:
    PkcsConvert();
};

#endif // PKCSCONVERT_H
