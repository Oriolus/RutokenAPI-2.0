#ifndef PKCS_TYPES_H
#define PKCS_TYPES_H

#include <string>
#include "Common.h"
#include "enums.h"


namespace pkcs11_core
{
    struct TokenInfo
    {
    public:
        std::string Label;
        std::string Manufacturer;
        std::string Model;
        std::string Serial;

        int64_t Flags;
        int64_t MaxSessionCount;
        int64_t CurrentSessionCount;
        int64_t MaxRWSessionCount;
        int64_t CurrentRWSessionCount;
        int64_t MaxPinLength;
        int64_t MinPinLength;
        int64_t TotalPublicMemory;
        int64_t FreePublicMemory;
        int64_t TotalPrivateMemory;
        int64_t FreePrivateMemory;

        int64_t Slot;

        std::string HardwareVersion;
        std::string FirmwareVersion;

        TokenInfo()
        {
            this->Label = std::string();
            this->Manufacturer = std::string();
            this->Model = std::string();
            this->Serial = std::string();
            this->Flags = -1;
            this->MaxSessionCount = -1;
            this->CurrentSessionCount = -1;
            this->MaxRWSessionCount = -1;
            this->CurrentRWSessionCount = -1;
            this->MaxPinLength = -1;
            this->MinPinLength = -1;
            this->TotalPrivateMemory = -1;
            this->TotalPublicMemory = -1;
            this->FreePrivateMemory = -1;
            this->FreePublicMemory = -1;
            this->Slot = -1;
            this->HardwareVersion = "";
            this->FirmwareVersion = "";
        }
    };

    struct InitInfo
    {
    public:
        InitInfo()
        {
            const char dApwd[] = "87654321";
            const char dUpwd[] = "12345678";
            const char dTLabel[] = "Default token label";
            AdminPin = std::string(dApwd, dApwd + sizeof(dApwd));
            UserPin = std::string(dUpwd, dUpwd + sizeof(dUpwd));
            TokenLabel = std::string(dTLabel, dTLabel + sizeof(dTLabel));

            MinAdminPinLen = 8;
            MinUserPinLen = 6;

            MaxAdminRetryCount = 10;
            MaxUserRetryCount = 10;

            Flags = (int64_t)TokenFlags::ADMIN_CHANGE_USER_PIN | (int64_t)TokenFlags::USER_CHANGE_USER_PIN;
        }

        std::string AdminPin;
        std::string UserPin;
        std::string TokenLabel;

        int64_t MinAdminPinLen;
        int64_t MinUserPinLen;
        int64_t MaxAdminRetryCount;
        int64_t MaxUserRetryCount;
        int64_t Flags;

    };
}

#endif // PKCS_TYPES_H
