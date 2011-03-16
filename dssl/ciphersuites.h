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
#ifndef __DSSL_CIPHERSUITES_H__
#define __DSSL_CIPHERSUITES_H__

#include "dssl_defs.h"

typedef enum SSL_KeyExchangeMethod_
{
	SSL_KEX_RSA,
	SSL_KEX_DH
} SSL_KeyExchangeMethod;

typedef enum SSL_SignatureMethod_
{
	SSL_SIG_RSA,
	SSL_SIG_DSS
} SSL_SignatureMethod;


struct _DSSL_CipherSuite
{
	uint16_t				id;
	uint16_t				ssl_version;

	uint16_t				key_ex;

	int						export_key_bits;

	const char*				enc;
	const char*				digest;
};

DSSL_CipherSuite* DSSL_GetCipherSuite( uint16_t id );
int DSSL_CipherSuiteExportable( DSSL_CipherSuite* ss );

#endif
