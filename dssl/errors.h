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
#ifndef __DSSL_ERRORS_H__
#define __DSSL_ERRORS_H__

#define NM_IS_FAILED( rc ) ((rc) < 0) 

#define DSSL_RC_WOULD_BOCK						1
#define DSSL_RC_OK								0
#define DSSL_E_OUT_OF_MEMORY					(-1)
#define DSSL_E_SSL_LOAD_CERTIFICATE				(-3)
#define DSSL_E_SSL_LOAD_PRIVATE_KEY				(-4)
#define DSSL_E_SSL_UNKNOWN_VERSION				(-5)
#define DSSL_E_INVALID_PARAMETER				(-6)
#define DSSL_E_SSL_PROTOCOL_ERROR				(-7)
#define DSSL_E_SSL_INVALID_RECORD_LENGTH 		(-8)
#define DSSL_E_UNSPECIFIED_ERROR				(-9)
#define DSSL_E_NOT_IMPL							(-10)
#define DSSL_E_SSL_SERVER_KEY_UNKNOWN			(-11)
#define DSSL_E_SSL_CANT_DECRYPT					(-12)
#define DSSL_E_SSL_CORRUPTED_PMS				(-13)
#define DSSL_E_SSL_PMS_VERSION_ROLLBACK			(-14)
#define DSSL_E_SSL_DECRYPTION_ERROR				(-15)
#define DSSL_E_SSL_BAD_FINISHED_DIGEST			(-16)
#define DSSL_E_TCP_CANT_REASSEMBLE				(-17)
#define DSSL_E_SSL_UNEXPECTED_TRANSMISSION		(-18)
#define DSSL_E_SSL_INVALID_MAC					(-19)
#define DSSL_E_SSL_SESSION_NOT_IN_CACHE			(-20)

#ifdef _DEBUG
	int NmDebugCatchError( int rc );
	#define NM_ERROR( rc ) NmDebugCatchError( rc )
#else
	#define NM_ERROR( rc ) (rc)
#endif

#endif
