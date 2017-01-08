/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2015, CJSC Aktiv-Soft. All rights reserved.         *
* Подробная информация:  http://www.rutoken.ru                           *
* Загрузка драйверов:    http://www.rutoken.ru/hotline/download/drivers/ *
* Техническая поддержка: http://www.rutoken.ru/hotline/                  *
*------------------------------------------------------------------------*
* Данный файл содержит объявление констант для работы с Рутокен при      *
* помощи библиотеки PKCS#11 на языке C                                   *
*************************************************************************/

#ifndef Common_H
#define Common_H

#ifdef _WIN32
	#include <stdio.h>
	#include <Windows.h>
	#include <WinCrypt.h>
	#include <process.h>
	#include <time.h>
#endif

#include "include_rt/wintypes.h"
#include "include_rt/rtpkcs11.h"
#include "include_rt/win2nix.h"

/************************************************************************
* Макросы                                                               *
************************************************************************/
/* Имя библиотеки PKCS#11 */
#ifdef _WIN32
    #define PKCS11_LIBRARY_NAME         "rtPKCS11.dll"
	#define PKCS11ECP_LIBRARY_NAME      "rtPKCS11ECP.dll"
#endif 
#ifdef __unix__
	#define PKCS11_LIBRARY_NAME         "librtpkcs11ecp.so"
	#define PKCS11ECP_LIBRARY_NAME      "librtpkcs11ecp.so"
#endif
/*
#ifdef __APPLE__
	#define PKCS11_LIBRARY_NAME         "librtpkcs11ecp.dylib"
	#define PKCS11ECP_LIBRARY_NAME      "librtpkcs11ecp.dylib"
#endif 	
*/
#ifndef TOKEN_TYPE_RUTOKEN
	#define TOKEN_TYPE_RUTOKEN 0x3 
#endif

#ifdef _WIN32
	#define HAVEMSCRYPTOAPI
#endif 

/* Вычисление размера массива */
#define arraysize(a)                (sizeof(a)/sizeof(a[0]))

#endif //PKCS11_COMMON_H
