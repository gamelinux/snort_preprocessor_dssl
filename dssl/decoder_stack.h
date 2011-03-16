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
#ifndef __DSSL_SSL_DECODER_STACK_H__
#define __DSSL_SSL_DECODER_STACK_H__

#include "decoder.h"
#include "dssl_defs.h"

#ifdef  __cplusplus
extern "C" {
#endif


typedef enum SSL_SessionState_
{
	SS_Initial,
	SS_SeenClientHello,
	SS_SeenServerHello,
	SS_Established,
	SS_FatalAlert,
	SS_SeenCloseNotify
}SSL_SessionState; 

struct dssl_decoder_stack_
{
	SSL_SessionState state;
	dssl_decoder	drecord;
	dssl_decoder	dhandshake;
	dssl_decoder	dappdata;
	dssl_decoder	dalert;
	dssl_decoder	dcss;

	EVP_CIPHER_CTX* cipher;
	const EVP_MD*	md;

	uint64_t		seq_num;
	u_char			mac_key[EVP_MAX_MD_SIZE];

	EVP_CIPHER_CTX* cipher_new;
	const EVP_MD*	md_new;
	u_char			mac_key_new[EVP_MAX_MD_SIZE];

	DSSL_Session*	sess;
};


void dssl_decoder_stack_init( dssl_decoder_stack* stack );
void dssl_decoder_stack_deinit( dssl_decoder_stack* stack );
int dssl_decoder_stack_process( dssl_decoder_stack* stack, NM_PacketDir dir, u_char* data, uint32_t len );

int sslc_is_decoder_stack_set( dssl_decoder_stack* s );

int dssl_decoder_stack_set( dssl_decoder_stack* s, DSSL_Session* sess, uint16_t version );

#ifdef  __cplusplus
}
#endif

#endif
