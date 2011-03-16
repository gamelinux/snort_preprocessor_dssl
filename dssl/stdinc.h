/*
** This file is a part of DSSL library.
**
** Copyright (C) 2003, Vladimir Shcherbakov <vladimir@ssltech.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#ifndef __DSSL_STDINC_H__
#define __DSSL_STDINC_H__

#include "ptypes.h"

#ifdef _WIN32
#pragma warning(push, 3)
#include <pcap.h>
#pragma warning(pop)
#else
#include <pcap.h>
#endif

#if defined(_WIN32)
  #ifdef _DEBUG
    #define _CRTDBG_MAP_ALLOC
    #include <stdlib.h>
    #include <crtdbg.h>
  #else
    #define _ASSERT( exp ) ((void)0)
  #endif

#elif defined (__linux)
  #ifdef _DEBUG
    #define _ASSERT( exp ) assert( exp )
  #else
    #define _ASSERT( exp ) ((void)0)
  #endif

#elif defined (__FreeBSD__)
  #ifdef _DEBUG
    #define _ASSERT( exp ) assert( exp )
  #else
    #define _ASSERT( exp ) ((void)0)
  #endif
#endif

#include "log.h"
#include "errors.h"

#ifndef FIELD_OFFSET
#define FIELD_OFFSET( t, f ) ((int) &(((t*)NULL)->f))
#endif

#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "dssl_defs.h"
#include "netdefs.h"

#endif
