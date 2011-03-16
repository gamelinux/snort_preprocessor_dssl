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
#ifndef __DSSL_SSL_SESSION_H__
#define __DSSL_SSL_SESSION_H__

#include "ssl_ctx.h"
#include "decoder_stack.h"

#ifdef  __cplusplus
extern "C" {
#endif


/* session flags */
/* SSF_CLIENT_SESSION_ID_SET means that ClientHello message contained non-null session id field */
#define SSF_CLIENT_SESSION_ID_SET	1
#define SSF_CLOSE_NOTIFY_RECEIVED	2		
#define SSF_FATAL_ALERT_RECEIVED	4

struct DSSL_Session_
{
	DSSL_Env*			env;

	uint16_t			version;		/* negotiated session version */
	uint16_t			client_version; /* actual client version */
	
	/* decoders */
	dssl_decoder_stack	c_dec; /* client-to-server stream decoder*/
	dssl_decoder_stack	s_dec; /* server-to-client stream decoder */

	u_char				client_random[SSL3_RANDOM_SIZE];
	u_char				server_random[SSL3_RANDOM_SIZE];

	u_char				PMS[SSL_MAX_MASTER_KEY_LENGTH];
	u_char				master_secret[SSL3_MASTER_SECRET_SIZE];

	u_char				session_id[DSSL_SESSION_ID_SIZE];
	uint32_t			flags;
	
	DSSL_ServerInfo*	ssl_si;

	uint16_t			cipher_suite;
	u_char				compression_method;

	EVP_MD_CTX			handshake_digest_sha;
	EVP_MD_CTX			handshake_digest_md5;

	int (*decode_finished_proc)( struct DSSL_Session_* sess, NM_PacketDir dir, u_char* data, uint32_t len );
	int (*caclulate_mac_proc)( dssl_decoder_stack* stack, u_char type, u_char* data, 
								uint32_t len, u_char* mac );

	DataCallbackProc	data_callback;
	ErrorCallbackProc	error_callback;
	void*				user_data;

};


void DSSL_SessionInit( DSSL_Env* env, DSSL_Session* s, DSSL_ServerInfo* si );
void DSSL_SessionDeInit( DSSL_Session* s );

void DSSL_SessionSetCallback( DSSL_Session* sess, DataCallbackProc data_callback, 
		ErrorCallbackProc error_callback, void* user_data );

/*
	DSSL_SessionProcessData:  Decodes captured network SSL session data
	dir - data (stream) direction
	{data, len} input should be a chunk of the reassembled TCP stream data.

	Deciphered SSL payload will be returned through the session data callback
	routine (see DSSL_SessionSetCallback)
*/
int DSSL_SessionProcessData( DSSL_Session* sess, NM_PacketDir dir, u_char* data, uint32_t len );

/* TODO: move to ssl_session_priv.h */
/* Internal routines */

EVP_PKEY* ssls_get_session_private_key( DSSL_Session* sess );
int ssls_decode_master_secret( DSSL_Session* sess );
int ssls_generate_keys( DSSL_Session* sess );
int ssls_set_session_version( DSSL_Session* sess, uint16_t ver );

int ssls_get_decode_buffer( DSSL_Session* sess, u_char** data, uint32_t len );
void ssls_release_decode_buffer( DSSL_Session* sess );

int ssls_lookup_session( DSSL_Session* sess );
void ssls_store_session( DSSL_Session* sess );

#ifdef  __cplusplus
}
#endif

#endif
