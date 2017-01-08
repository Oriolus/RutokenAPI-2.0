#include "texception.h"

TException::TException()
{
    this->message = std::string("Unknown error");
    this->code = Error::OK;
}

TException::TException(const char *message, Error code)
{
    this->message = std::string(message);
    this->code = code;
}

TException::TException(std::string &message, Error code)
{
    this->message = std::string(message);
    this->code = code;
}

TException::TException(const char *message, size_t msgLength, Error code)
{
    this->message = std::string(message, msgLength);
    this->code = code;
}
