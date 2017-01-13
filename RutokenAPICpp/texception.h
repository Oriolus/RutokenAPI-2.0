#ifndef TEXCEPTION_H
#define TEXCEPTION_H

#include <string>
#include "enums.h"

namespace pkcs11_core
{
    class TException
    {
    private:
        std::string message;
        Error code;
    public:
        TException();
        TException(std::string &message, Error code);
        TException(const char *message, Error code);
        TException(const char *message, size_t msgLength, Error code);
        std::string     GetReason() { return this->message; }
        Error           GetCode() { return this->code; }
    };
}

#endif // TEXCEPTION_H
