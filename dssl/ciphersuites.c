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
#include "stdinc.h"
#include "ciphersuites.h"

static DSSL_CipherSuite suites[] = 
{
	{ 0x01, SSL3_VERSION, SSL_KEX_RSA, 0, "NULL", "MD5" },
	{ 0x02, SSL3_VERSION, SSL_KEX_RSA, 0, "NULL", "SHA1" },
	{ 0x03, SSL3_VERSION, SSL_KEX_RSA,	40, "RC4", "MD5" },
	{ 0x04, SSL3_VERSION, SSL_KEX_RSA, 0, "RC4", "MD5" },
	{ 0x05, SSL3_VERSION, SSL_KEX_RSA, 0, "RC4", "SHA1" },
	{ 0x06, SSL3_VERSION, SSL_KEX_RSA, 40, "RC2", "MD5" },
	{ 0x07, SSL3_VERSION, SSL_KEX_RSA, 0, "IDEA", "SHA1" },
	{ 0x08, SSL3_VERSION, SSL_KEX_RSA, 40, "DES", "SHA1" },
	{ 0x09, SSL3_VERSION, SSL_KEX_RSA, 0, "DES", "SHA1" },
	{ 0x0A, SSL3_VERSION, SSL_KEX_RSA, 0, "DES3", "SHA1" },
	{ 0x2F, TLS1_VERSION, SSL_KEX_RSA, 0, SN_aes_128_cbc, "SHA1" },
	{ 0x35, TLS1_VERSION, SSL_KEX_RSA,	0, SN_aes_256_cbc, "SHA1" }
};

static int compare_cipher_suites( const void* key, const void* elem )
{
	uint16_t id = *((uint16_t*)key);
	DSSL_CipherSuite* cs = (DSSL_CipherSuite*) elem;

	return id - cs->id;
}

DSSL_CipherSuite* DSSL_GetCipherSuite( uint16_t id )
{
	return (DSSL_CipherSuite*) bsearch( &id, suites, 
			sizeof(suites)/sizeof(suites[0]), sizeof(suites[0]),
			compare_cipher_suites );
}

int DSSL_CipherSuiteExportable( DSSL_CipherSuite* ss )
{
	return ss->export_key_bits != 0;
}
