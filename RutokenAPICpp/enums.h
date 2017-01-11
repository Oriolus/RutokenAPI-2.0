#ifndef ENUMS_H
#define ENUMS_H

#include "include_rt/rtpkcs11.h"
#include <cstdint>

namespace pkcs11_core
{

enum class Key : uint64_t
{
    GOST28147 =                         CKK_GOST28147,
    GOSTR3410_256 =                     CKK_GOSTR3410,
    GOSTR3410_512 =                     CKK_GOSTR3410_512
};

enum class Objects : uint64_t
{
    DATA =                              CKO_DATA,
    PUBLIC_KEY =                        CKO_PUBLIC_KEY,
    PRIVATE_KEY =                       CKO_PRIVATE_KEY,
    SECRET_KEY =                        CKO_SECRET_KEY,
    CERTIFICATE =                       CKO_CERTIFICATE,
    MECHANIST =                         CKO_MECHANISM
};

enum class Attribute : uint64_t
{
    COPYABLE =                          CKA_COPYABLE,
    EXTRACTABLE =                       CKA_EXTRACTABLE,
    VALUE_BITS =                        CKA_VALUE_BITS,
    VALUE_LEN =                         CKA_VALUE_LEN,
    LOCAL =                             CKA_LOCAL,
    NEVER_EXTRACTABLE =                 CKA_NEVER_EXTRACTABLE,
    ALWAYS_SENSITIVE =                  CKA_ALWAYS_SENSITIVE,
    KEY_GEN_MECHANISM =                 CKA_KEY_GEN_MECHANISM,
    MODIFIABLE =                        CKA_MODIFIABLE,
    CLASS =                             CKA_CLASS,
    LABEL =                             CKA_LABEL,
    ID =                                CKA_ID,
    KEY_TYPE =                          CKA_KEY_TYPE,
    TOKEN_ =                            CKA_TOKEN,
    PRIVATE =                           CKA_PRIVATE,
    ENCRYPT =                           CKA_ENCRYPT,
    DECRYPT =                           CKA_DECRYPT,
    SIGN =                              CKA_SIGN,
    VERIFY =                            CKA_VERIFY,
    DERIVE =                            CKA_DERIVE,
    SENSITIVE =                         CKA_SENSITIVE,
    SUBJECT =                           CKA_SUBJECT,
    APPLICATION =                       CKA_APPLICATION,
    VALUE =                             CKA_VALUE,
    WRAP =                              CKA_WRAP,
    UNWRAP =                            CKA_UNWRAP,
    START_DATE =                        CKA_START_DATE,
    END_DATE =                          CKA_END_DATE,
    GOST3410_PARAMS =                   CKA_GOSTR3410_PARAMS,
    GOST3411_PARAMS =                   CKA_GOSTR3411_PARAMS,
    GOST28147_PARAMS =                  CKA_GOST28147_PARAMS
};

enum class KeyGenerateMechanism : int64_t
{
    GOSTR3410_256 =                     CKM_GOSTR3410_KEY_PAIR_GEN,
    GOSTR3410_512 =                     CKM_GOSTR3410_512_KEY_PAIR_GEN,

    GOST28147 =                         CKM_GOST28147_KEY_GEN,

    GOSTR3410_256_DERIVE =              CKM_GOSTR3410_DERIVE,
    GOSTR3410_512_DERIVE =              CKM_GOSTR3410_12_DERIVE
};

enum class SymmetricMechanism : int64_t
{
    GOST28147_ECB =                     CKM_GOST28147_ECB,
    GOST28147_OFB =                     CKM_GOST28147,
    GOST28147_MAC =                     CKM_GOST28147_MAC,

    GOSTR3411_94_256 =                  CKM_GOSTR3411,
    GOSTR3411_12_256 =                  CKM_GOSTR3411_12_256,
    GOSTR3411_12_512 =                  CKM_GOSTR3411_12_512
};

enum class AsymmetricMechanism : int64_t
{
    GOSTR3410_01_256 =                  CKM_GOSTR3410,
    GOSTR3410_12_256 =                  CKM_GOSTR3410,
    GOSTR3410_12_512 =                  CKM_GOSTR3410_512,

    GOSTR3410_WITH_GOST_R3411_94_256 =  CKM_GOSTR3410_WITH_GOSTR3411,
    GOSTR3410_WITH_GOST_R3411_12_256 =  CKM_GOSTR3410_WITH_GOSTR3411_12_256,
    GOSTR3410_WITH_GOST_R3411_12_512 =  CKM_GOSTR3410_WITH_GOSTR3411_12_512
};

enum class User : int64_t
{
    SECURIRY_OFFICER =                  CKU_SO,
    USER =                              CKU_USER
};

enum class TokenFlags : int64_t
{
    ADMIN_CHANGE_USER_PIN =             TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN,
    ADMIN_PIN_NOT_DEFAULT =             TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT,
    CAN_CHANGE_SM_MODE =                TOKEN_FLAGS_CAN_CHANGE_SM_MODE,
    FW_CHECKSUM_INVALID =               TOKEN_FLAGS_FW_CHECKSUM_INVALID,
    FW_CHECKSUM_UNAVAILIBLE =           TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE,
    HAS_FLASH_DRIVE =                   TOKEN_FLAGS_HAS_FLASH_DRIVE,
    SUPPORT_FKN =                       TOKEN_FLAGS_SUPPORT_FKN,
    SUPPORT_SM =                        TOKEN_FLAGS_SUPPORT_SM,
    USER_CHANGE_USER_PIN =              TOKEN_FLAGS_USER_CHANGE_USER_PIN,
    USER_PIN_NOT_DEFAULT =              TOKEN_FLAGS_USER_PIN_NOT_DEFAULT
};

enum class Error : uint64_t
{
    OK =                                CKR_OK,
    CANCEL =                            CKR_CANCEL,
    HOST_MEMORY =                       CKR_HOST_MEMORY,
    SLOT_ID_INVALID =                   CKR_SLOT_ID_INVALID,
    GENERAL_ERROR =                     CKR_GENERAL_ERROR,
    FUNCTION_FAILED =                   CKR_FUNCTION_FAILED,
    ARGUMENTS_BAD =                     CKR_ARGUMENTS_BAD,
    NO_EVENT =                          CKR_NO_EVENT,
    NEED_TO_CREATE_THREADS =            CKR_NEED_TO_CREATE_THREADS,
    CANT_LOCK =                         CKR_CANT_LOCK,
    ATTRIBUTE_READ_ONLY =               CKR_ATTRIBUTE_READ_ONLY,
    ATTRIBUTE_SENSITIVE =               CKR_ATTRIBUTE_SENSITIVE,
    ATTRIBUTE_TYPE_INVALID =            CKR_ATTRIBUTE_TYPE_INVALID,
    ATTRIBUTE_VALUE_INVALID =           CKR_ATTRIBUTE_VALUE_INVALID,
    DATA_INVALID =                      CKR_DATA_INVALID,
    DATA_LEN_RANGE =                    CKR_DATA_LEN_RANGE,
    DEVICE_ERROR =                      CKR_DEVICE_ERROR,
    DEVICE_MEMORY =                     CKR_DEVICE_MEMORY,
    DEVICE_REMOVED =                    CKR_DEVICE_REMOVED,
    ENCRYPTED_DATA_INVALID =            CKR_ENCRYPTED_DATA_INVALID,
    ENCRYPTED_DATA_LEN_RANGE =          CKR_ENCRYPTED_DATA_LEN_RANGE,
    FUNCTION_CANCELED =                 CKR_FUNCTION_CANCELED,
    FUNCTION_NOT_PARALLEL =             CKR_FUNCTION_NOT_PARALLEL,
    FUNCTION_NOT_SUPPORTED =            CKR_FUNCTION_NOT_SUPPORTED,
    KEY_HANDLE_INVALID =                CKR_KEY_HANDLE_INVALID,
    KEY_SIZE_RANGE =                    CKR_KEY_SIZE_RANGE,
    KEY_TYPE_INCONSISTENT =             CKR_KEY_TYPE_INCONSISTENT,
    KEY_NOT_NEEDED =                    CKR_KEY_NOT_NEEDED,
    KEY_CHANGED =                       CKR_KEY_CHANGED,
    KEY_NEEDED =                        CKR_KEY_NEEDED,
    KEY_INDIGESTIBLE =                  CKR_KEY_INDIGESTIBLE,
    KEY_FUNCTION_NOT_PERMITTED =        CKR_KEY_FUNCTION_NOT_PERMITTED,
    KEY_NOT_WRAPPABLE =                 CKR_KEY_NOT_WRAPPABLE,
    KEY_UNEXTRACTABLE =                 CKR_KEY_UNEXTRACTABLE,
    MECHANISM_INVALID =                 CKR_MECHANISM_INVALID,
    MECHANISM_PARAM_INVALID =           CKR_MECHANISM_PARAM_INVALID,
    OBJECT_HANDLE_INVALID =             CKR_OBJECT_HANDLE_INVALID,
    OPERATION_ACTIVE =                  CKR_OPERATION_ACTIVE,
    OPERATION_NOT_INITIALIZED =         CKR_OPERATION_NOT_INITIALIZED,
    PIN_INCORRECT =                     CKR_PIN_INCORRECT,
    PIN_INVALID =                       CKR_PIN_INVALID,
    PIN_LEN_RANGE =                     CKR_PIN_LEN_RANGE,
    PIN_EXPIRED =                       CKR_PIN_EXPIRED,
    PIN_LOCKED =                        CKR_PIN_LOCKED,
    SESSION_CLOSED =                    CKR_SESSION_CLOSED,
    SESSION_COUNT =                     CKR_SESSION_COUNT,
    SESSION_HANDLE_INVALID =            CKR_SESSION_HANDLE_INVALID,
    SESSION_PARALLEL_NOT_SUPPORTED =    CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    SESSION_READ_ONLY =                 CKR_SESSION_READ_ONLY,
    SESSION_EXISTS =                    CKR_SESSION_EXISTS,
    SESSION_READ_ONLY_EXISTS =          CKR_SESSION_READ_ONLY_EXISTS,
    SESSION_READ_WRITE_SO_EXISTS =      CKR_SESSION_READ_WRITE_SO_EXISTS,
    SIGNATURE_INVALID =                 CKR_SIGNATURE_INVALID,
    SIGNATURE_LEN_RANGE =               CKR_SIGNATURE_LEN_RANGE,
    TEMPLATE_INCOMPLETE =               CKR_TEMPLATE_INCOMPLETE,
    TEMPLATE_INCONSISTENT =             CKR_TEMPLATE_INCONSISTENT,
    TOKEN_NOT_PRESENT =                 CKR_TOKEN_NOT_PRESENT,
    TOKEN_NOT_RECOGNIZED =              CKR_TOKEN_NOT_RECOGNIZED,
    TOKEN_WRITE_PROTECTED =             CKR_TOKEN_WRITE_PROTECTED,
    UNWRAPPING_KEY_HANDLE_INVALID =     CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    UNWRAPPING_KEY_SIZE_RANGE =         CKR_UNWRAPPING_KEY_SIZE_RANGE,
    UNWRAPPING_KEY_TYPE_INCONSISTENT =  CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    USER_ALREADY_LOGGED_IN =            CKR_USER_ALREADY_LOGGED_IN,
    USER_NOT_LOGGED_IN =                CKR_USER_NOT_LOGGED_IN,
    USER_PIN_NOT_INITIALIZED =          CKR_USER_PIN_NOT_INITIALIZED,
    USER_TYPE_INVALID =                 CKR_USER_TYPE_INVALID,
    USER_ANOTHER_ALREADY_LOGGED_IN =    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    USER_TOO_MANY_TYPES =               CKR_USER_TOO_MANY_TYPES,
    WRAPPED_KEY_INVALID =               CKR_WRAPPED_KEY_INVALID,
    WRAPPED_KEY_LEN_RANGE =             CKR_WRAPPED_KEY_LEN_RANGE,
    WRAPPING_KEY_HANDLE_INVALID =       CKR_WRAPPING_KEY_HANDLE_INVALID,
    WRAPPING_KEY_SIZE_RANGE =           CKR_WRAPPING_KEY_SIZE_RANGE,
    WRAPPING_KEY_TYPE_INCONSISTENT =    CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    RANDOM_SEED_NOT_SUPPORTED =         CKR_RANDOM_SEED_NOT_SUPPORTED,
    RANDOM_NO_RNG =                     CKR_RANDOM_NO_RNG,
    DOMAIN_PARAMS_INVALID =             CKR_DOMAIN_PARAMS_INVALID,
    BUFFER_TOO_SMALL =                  CKR_BUFFER_TOO_SMALL,
    SAVED_STATE_INVALID =               CKR_SAVED_STATE_INVALID,
    INFORMATION_SENSITIVE =             CKR_INFORMATION_SENSITIVE,
    STATE_UNSAVEABLE =                  CKR_STATE_UNSAVEABLE,
    CRYPTOKI_NOT_INITIALIZED =          CKR_CRYPTOKI_NOT_INITIALIZED,
    CRYPTOKI_ALREADY_INITIALIZED =      CKR_CRYPTOKI_ALREADY_INITIALIZED,
    MUTEX_BAD =                         CKR_MUTEX_BAD,
    MUTEX_NOT_LOCKED =                  CKR_MUTEX_NOT_LOCKED,
    NEW_PIN_MODE =                      CKR_NEW_PIN_MODE,
    NEXT_OTP =                          CKR_NEXT_OTP,
    FUNCTION_REJECTED =                 CKR_FUNCTION_REJECTED,
    VENDOR_DEFINED =                    CKR_VENDOR_DEFINED,
    FUNCITON_LIST_NOT_LOADED =          0x10000000,
    KEY_HANDLE_HOT_FOUND =              0x10000001,
    MANY_HANDLES_FOUND =                0x10000002,
    SAME_KEY_ID_EXISTS =                0x10000003,
    UNKNOWN_KEY_CLASS =                 0x10000004,
    LIBRARI_NOT_LOADED =                0x10000005,
    FUNCTION_LIST_NOT_INITIALIZED =     0x10000006
};

}

#endif // ENUMS_H

