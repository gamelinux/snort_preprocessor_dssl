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
#include "session.h"
#include "ssl_session.h"
#include "ssl_decode_hs.h"
#include "ssl_utils.h"
#include "ssl_mac.h"
#include "ciphersuites.h"
#include "ssl_sessionkey_table.h"
#include <openssl/evp.h>

void DSSL_SessionInit( DSSL_Env* env, DSSL_Session* s, DSSL_ServerInfo* si )
{
	_ASSERT( s );

#ifdef NM_TRACE_SSL_SESSIONS
	DEBUG_TRACE0( "DSSL_SessionInit\n" );
#endif
	memset( s, 0, sizeof(*s) );

	s->ssl_si = si;
	s->env = env;

	dssl_decoder_stack_init( &s->c_dec );
	dssl_decoder_stack_init( &s->s_dec );

	EVP_MD_CTX_init( &s->handshake_digest_md5 );
	EVP_MD_CTX_init( &s->handshake_digest_sha );
}


void DSSL_SessionDeInit( DSSL_Session* s )
{
#ifdef NM_TRACE_SSL_SESSIONS
	DEBUG_TRACE0( "DSSL_SessionDeInit\n" );
#endif

	if( s->env ) DSSL_EnvOnSessionClosing( s->env, s );

	dssl_decoder_stack_deinit( &s->c_dec );
	dssl_decoder_stack_deinit( &s->s_dec );

	EVP_MD_CTX_cleanup( &s->handshake_digest_md5 );
	EVP_MD_CTX_cleanup( &s->handshake_digest_sha );
}


void DSSL_SessionSetCallback( DSSL_Session* sess, DataCallbackProc data_callback, 
							ErrorCallbackProc error_callback, void* user_data )
{
	_ASSERT( sess );
	
	sess->data_callback = data_callback;
	sess->error_callback = error_callback;
	sess->user_data = user_data;
}



int DSSL_SessionProcessData( DSSL_Session* sess, NM_PacketDir dir, u_char* data, uint32_t len )
{
	int rc = DSSL_RC_OK;
	dssl_decoder_stack* dec = NULL;

	if( dir == ePacketDirInvalid ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	dec = (dir == ePacketDirFromClient) ? &sess->c_dec : &sess->s_dec;

	if( !sslc_is_decoder_stack_set( dec ) )
	{
		uint16_t ver = 0;

		if( dir == ePacketDirFromClient )
		{
			rc = ssl_detect_client_hello_version( data, len, &ver );
		}
		else
		{
			rc = ssl_detect_server_hello_version( data, len, &ver );
			/* update the client decoder after the server have declared the actual version 
			of the session */
			if( rc == DSSL_RC_OK && sess->version != ver )
			{
				rc = dssl_decoder_stack_set( &sess->c_dec, sess, ver );
			}
			ssls_set_session_version( sess, ver );
		}

		if( rc == DSSL_RC_OK ) 
		{
			rc = dssl_decoder_stack_set( dec, sess, ver );
		}
	}

	if( rc == DSSL_RC_OK ) rc = dssl_decoder_stack_process( dec, dir, data, len );

	if( NM_IS_FAILED( rc ) && sess->error_callback )
	{
		sess->error_callback( sess->user_data, rc );
	}

	return rc;
}


EVP_PKEY* ssls_get_session_private_key( DSSL_Session* sess )
{
	if( sess->ssl_si == NULL ) return NULL;
	return sess->ssl_si->pkey;
}


int ssls_set_session_version( DSSL_Session* sess, uint16_t ver )
{
	int rc = DSSL_RC_OK;

	sess->version = ver;

	switch( ver )
	{
	case SSL3_VERSION:
		sess->decode_finished_proc = ssl3_decode_finished;
		sess->caclulate_mac_proc  = ssl3_calculate_mac;
		break;

	case TLS1_VERSION:
		sess->decode_finished_proc = tls1_decode_finished;
		sess->caclulate_mac_proc = tls1_calculate_mac;
		break;

	default:
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
		break;
	}

	return rc;
}


int ssls_decode_master_secret( DSSL_Session* sess )
{
	switch( sess->version )
	{
	case SSL3_VERSION:
		return ssl3_PRF( sess->PMS, SSL_MAX_MASTER_KEY_LENGTH, 
					sess->client_random, SSL3_RANDOM_SIZE, 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->master_secret, sizeof( sess->master_secret ) );

	case TLS1_VERSION:
		return tls1_PRF( sess->PMS, SSL_MAX_MASTER_KEY_LENGTH, 
					"master secret", 
					sess->client_random, SSL3_RANDOM_SIZE, 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->master_secret, sizeof( sess->master_secret ) );

	default:
		return NM_ERROR( DSSL_E_NOT_IMPL );
	}
}


static void ssl3_generate_export_iv( u_char* random1, u_char* random2, u_char* out )
{
    MD5_CTX md5;
    
    MD5_Init( &md5 );
	MD5_Update( &md5, random1, SSL3_RANDOM_SIZE );
	MD5_Update( &md5, random2, SSL3_RANDOM_SIZE );
    MD5_Final( out, &md5 );
}

#define TLS_MAX_KEYBLOCK_LEN ((EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + EVP_MAX_MD_SIZE)*2)
int ssls_generate_keys( DSSL_Session* sess )
{
	DSSL_CipherSuite* suite = NULL;
	const EVP_CIPHER* c = NULL;
	const EVP_MD* digest = NULL;
	u_char* c_mac = NULL;
	u_char* c_wk = NULL;
	u_char* c_iv = NULL;
	u_char* s_mac = NULL;
	u_char* s_wk = NULL;
	u_char* s_iv = NULL;
	u_char export_iv_block[EVP_MAX_IV_LENGTH*2];

	u_char export_c_wk[EVP_MAX_KEY_LENGTH];
	u_char export_s_wk[EVP_MAX_KEY_LENGTH];
	
	u_char keyblock[ TLS_MAX_KEYBLOCK_LEN ];
	uint32_t keyblock_len = 0;

	uint32_t iv_len = 0;
	uint32_t wk_len = 0;
	uint32_t digest_len = 0;

	EVP_CIPHER_CTX* c_cipher = NULL;
	EVP_CIPHER_CTX* s_cipher = NULL;

	int rc = DSSL_RC_OK;

	if( sess->c_dec.cipher_new != NULL )
	{
		_ASSERT( FALSE );
		EVP_CIPHER_CTX_cleanup( sess->c_dec.cipher_new );
		free( sess->c_dec.cipher_new );
		sess->c_dec.cipher_new = NULL;
	}

	if( sess->s_dec.cipher_new != NULL )
	{
		_ASSERT( FALSE );
		EVP_CIPHER_CTX_cleanup( sess->s_dec.cipher_new );
		free( sess->s_dec.cipher_new );
		sess->s_dec.cipher_new = NULL;
	}

	suite = DSSL_GetCipherSuite( sess->cipher_suite );
	if( !suite ) return NM_ERROR( DSSL_E_SSL_CANT_DECRYPT );

	c = EVP_get_cipherbyname( suite->enc );
	digest = EVP_get_digestbyname( suite->digest );

	/* calculate key length and IV length */
	if( c != NULL ) 
	{
		if( DSSL_CipherSuiteExportable( suite ) )
		{ wk_len = suite->export_key_bits / 8; }
		else 
		{ wk_len = EVP_CIPHER_key_length( c ); }

		iv_len = EVP_CIPHER_iv_length( c );
	}
	if( digest != NULL ) digest_len = EVP_MD_size( digest );

	/* calculate total keyblock length */
	keyblock_len = (wk_len + digest_len + iv_len)*2;
	if( !keyblock_len ) return DSSL_RC_OK;

	if( sess->version == TLS1_VERSION )
	{
		rc = tls1_PRF( sess->master_secret, sizeof( sess->master_secret ), 
					"key expansion", 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->client_random, SSL3_RANDOM_SIZE,
					keyblock, keyblock_len );
	}
	else
	{
		rc = ssl3_PRF( sess->master_secret, sizeof( sess->master_secret ),
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->client_random, SSL3_RANDOM_SIZE,
					keyblock, keyblock_len );
	}

	/* init keying material pointers */
	if( rc == DSSL_RC_OK )
	{
		u_char* p = keyblock;

		if( digest_len )
		{
			c_mac = p; p+= digest_len;
			s_mac = p; p+= digest_len;
		}

		if( c != NULL )
		{
			c_wk = p; p+= wk_len;
			s_wk = p; p+= wk_len;

			/* generate final server and client write keys for exportable ciphers */
			if( DSSL_CipherSuiteExportable( suite ) )
			{
				int final_wk_len =  EVP_CIPHER_key_length( c );
				if( sess->version == TLS1_VERSION )
				{
					tls1_PRF( c_wk, wk_len, "client write key", 
							sess->client_random, SSL3_RANDOM_SIZE,
							sess->server_random, SSL3_RANDOM_SIZE,
							export_c_wk, final_wk_len );
					
					tls1_PRF( s_wk, wk_len, "server write key", 
							sess->client_random, SSL3_RANDOM_SIZE,
							sess->server_random, SSL3_RANDOM_SIZE,
							export_s_wk, final_wk_len );
				}
				else
				{
					MD5_CTX md5;

					_ASSERT( sess->version == SSL3_VERSION );
					MD5_Init( &md5 );
					MD5_Update( &md5, c_wk, wk_len );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_c_wk, &md5 );

					MD5_Init( &md5 );
					MD5_Update( &md5, s_wk, wk_len );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_s_wk, &md5 );

				}
				c_wk = export_c_wk;
				s_wk = export_s_wk;
				wk_len = final_wk_len;
			}
		}
		
		if( iv_len )
		{
			if( DSSL_CipherSuiteExportable( suite ) )
			{
				if( sess->version == TLS1_VERSION )
				{
					tls1_PRF( NULL, 0, "IV block",
							sess->client_random, SSL3_RANDOM_SIZE, 
							sess->server_random, SSL3_RANDOM_SIZE,
							export_iv_block, iv_len*2 );
				}
				else
				{
					MD5_CTX md5;

					_ASSERT( sess->version == SSL3_VERSION );

					MD5_Init( &md5 );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_iv_block, &md5 );

					MD5_Init( &md5 );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_iv_block + iv_len, &md5 );
				}
				c_iv = export_iv_block;
				s_iv = export_iv_block + iv_len;
			}
			else
			{
				c_iv = p; p+= iv_len;
				s_iv = p; p+= iv_len;
			}
		}
		else
		{
			c_iv = s_iv = NULL;
		}
	}

	/* create ciphers */
	if(  c != NULL && rc == DSSL_RC_OK )
	{
		c_cipher = (EVP_CIPHER_CTX*) malloc( sizeof(EVP_CIPHER_CTX) );
		s_cipher = (EVP_CIPHER_CTX*) malloc( sizeof(EVP_CIPHER_CTX) );

		if( !c_cipher || !s_cipher ) 
		{
			rc = NM_ERROR( DSSL_E_OUT_OF_MEMORY );
		}
	}

	/* init ciphers */
	if( c != NULL && rc == DSSL_RC_OK )
	{
		EVP_CIPHER_CTX_init( c_cipher );
		EVP_CipherInit( c_cipher, c, c_wk, c_iv, 0 );

		EVP_CIPHER_CTX_init( s_cipher );
		EVP_CipherInit( s_cipher, c, s_wk, s_iv, 0 );
	}

	/* set session data */
	if( rc == DSSL_RC_OK )
	{
		_ASSERT( sess->c_dec.cipher_new == NULL );
		_ASSERT( sess->s_dec.cipher_new == NULL );

		sess->c_dec.cipher_new = c_cipher; c_cipher = NULL;
		sess->s_dec.cipher_new = s_cipher; s_cipher = NULL;

		if( digest )
		{
			_ASSERT( EVP_MD_size( digest ) == (int)digest_len );
			sess->c_dec.md_new = digest;
			sess->s_dec.md_new = digest;
			memcpy( sess->c_dec.mac_key_new, c_mac, digest_len );
			memcpy( sess->s_dec.mac_key_new, s_mac, digest_len );
		}
	}

	/* cleanup */
	OPENSSL_cleanse( keyblock, keyblock_len );

	if( c_cipher )
	{
		free( c_cipher );
		c_cipher = NULL;
	}

	if( s_cipher )
	{
		free( c_cipher );
		c_cipher = NULL;
	}

	return rc;
}


int ssls_lookup_session( DSSL_Session* sess )
{
	DSSL_SessionKeyData* sess_data = NULL;

	_ASSERT( sess );
	_ASSERT( sess->env );
	
	if( sess->env->session_cache )
	{
		sess_data = dssl_SessionKT_Find( sess->env->session_cache, sess->session_id );
	}

	if( !sess_data ) return NM_ERROR( DSSL_E_SSL_SESSION_NOT_IN_CACHE );

	dssl_SessionKT_AddRef( sess_data );
	memcpy( sess->master_secret, sess_data->master_secret, SSL3_MASTER_SECRET_SIZE );

	return DSSL_RC_OK;
}

void ssls_store_session( DSSL_Session* sess )
{
	DSSL_SessionKeyData* sess_data = NULL;

	_ASSERT( sess );
	_ASSERT( sess->env );
	if( !sess->env->session_cache ) return;

	sess_data = dssl_SessionKT_Find( sess->env->session_cache, sess->session_id );

	if( sess_data )
	{
		memcpy( sess_data->master_secret, sess->master_secret, SSL3_MASTER_SECRET_SIZE );
	}
	else
	{
		dssl_SessionKT_Add( sess->env->session_cache, sess );
	}
}


#ifdef NM_MULTI_THREADED_SSL
	#error "Multithreading is not implemented for SSL session decode buffer!"
#else
int ssls_get_decode_buffer( DSSL_Session* sess, u_char** data, uint32_t len )
{
	if(!data || !len ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	if( len > sizeof(sess->env->decomp_buffer))
	{
		_ASSERT( FALSE ); /*decomp_buffer is supposed to fit the biggest possible SSL record!*/
		return NM_ERROR( DSSL_E_OUT_OF_MEMORY );
	}

	(*data) = sess->env->decomp_buffer;
	return DSSL_RC_OK;
}

void ssls_release_decode_buffer( DSSL_Session* sess )
{
	/* no-op in a single threaded mode */
	sess;
}
#endif