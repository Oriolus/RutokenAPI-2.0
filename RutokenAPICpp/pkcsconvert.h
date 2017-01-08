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
    static string       Trim(string &str);
private:
    PkcsConvert();
};

#endif // PKCSCONVERT_H
