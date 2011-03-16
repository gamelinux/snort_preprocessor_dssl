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
#include "ssl_session.h"
#include "ssl_decode_hs.h"
#include "ssl_decode.h"
#include "decoder_stack.h"

/* Local prototypes */
static void ssl3_init_handshake_digests( DSSL_Session* sess );
static void ssl3_update_handshake_digests( DSSL_Session* sess, u_char* data, uint32_t len );


/* ========== ClientHello, ServerHello ========== */
static int ssl2_decode_client_hello( DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	uint32_t recLen = ((data[0] & 0x7f) << 8) | data[1];
	int rc = DSSL_RC_OK;
	uint32_t sessionIdLen = 0, challengeLen = 0, cypherSpecLen = 0;

	_ASSERT( processed != NULL );
	*processed = 0;

	if( len < recLen + SSL20_CLIENT_HELLO_HDR_LEN ) return DSSL_RC_WOULD_BOCK;
	if( recLen < SSL20_CLIENT_HELLO_MIN_LEN ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH ); 

#ifdef NM_TRACE_SSL_STATE
	DEBUG_TRACE0( "SSLv2 ClientHello" );
#endif
	
	if( data[3] == 0 && data[4] == 2 )
	{
		sess->client_version = SSL2_VERSION;
		ssls_set_session_version( sess, SSL2_VERSION );
	}
	else if( data[3] == 3 ) 
	{
		/* SSLv3 or TLS1 in a v2 header */
		sess->client_version = MAKE_UINT16(data[3], data[4]);
		ssls_set_session_version( sess, MAKE_UINT16(data[3], data[4]) );
		
		ssl3_init_handshake_digests( sess );
		ssl3_update_handshake_digests( sess, data + SSL20_CLIENT_HELLO_HDR_LEN, recLen );
	}
	else
	{
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	/*	validate the record format */
	if( rc == DSSL_RC_OK )
	{
		/* CIPHER-SPECS-LENGTH */
		cypherSpecLen = MAKE_UINT16( data[5], data[6] );
		/* SESSION-ID-LENGTH */
		sessionIdLen = MAKE_UINT16( data[7], data[8] ); 
		/* CHALLENGE-LENGTH */
		challengeLen = MAKE_UINT16( data[9], data[10] ); 

		if( challengeLen + sessionIdLen + cypherSpecLen + SSL20_CLIENT_HELLO_MIN_LEN != recLen ) 
			rc = NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	}

	/* validate and set the session ID */
	
	if( rc == DSSL_RC_OK )
	{
		if( sessionIdLen == 16 )
		{
			u_char* sessionId = data + SSL20_CLIENT_HELLO_MIN_LEN + 
					SSL20_CLIENT_HELLO_HDR_LEN + cypherSpecLen;

			_ASSERT( sessionIdLen <= sizeof( sess->session_id ) );
			memset( sess->session_id, 0, sizeof( sess->session_id ) );
			memcpy( sess->session_id, sessionId, sessionIdLen );
			sess->flags |= SSF_CLIENT_SESSION_ID_SET;

		}
		else
		{
			sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
			if (sessionIdLen != 0 )
			{
				/* session ID length must be either 16 or 0 for SSL v2 */
				rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
			}
		}
	}

	/* validate and set the client random aka Challenge */
	if( rc == DSSL_RC_OK )
	{
		if( challengeLen < 16 || challengeLen > 32 )
		{
			rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
		}
		else
		{
			_ASSERT( challengeLen <= sizeof( sess->client_random ) );
			memset( sess->client_random, 0, sizeof( sess->client_random ) );
			memcpy( sess->client_random, data + recLen + SSL20_CLIENT_HELLO_HDR_LEN - challengeLen, challengeLen );
		}
	}

	if( rc == DSSL_RC_OK ) *processed = recLen + SSL20_CLIENT_HELLO_HDR_LEN;

	return rc;
}


static int ssl3_decode_client_hello( DSSL_Session* sess, u_char* data, uint32_t len )
{
	u_char* org_data = data;

	if( data[0] != 3 || data[1] > 1) return NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );

	sess->client_version = MAKE_UINT16( data[0], data[1] );
	ssls_set_session_version( sess, MAKE_UINT16( data[0], data[1] ) );

	data+= 2;

	if( data + 32 > org_data + len ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

	memcpy( sess->client_random, data, 32 );
	data+= 32;

	/* check session ID length */
	if( data[0] > 32 ) return NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );

	if( data[0] > 0 )
	{
		if( data + data[0] > org_data + len ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

		memcpy( sess->session_id, data+1, data[0] );
		sess->flags |= SSF_CLIENT_SESSION_ID_SET;

		data += data[0] + 1;
	}
	else
	{
		sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
		++data;
	}


	return DSSL_RC_OK;
}


static int ssl3_decode_server_hello( DSSL_Session* sess, u_char* data, uint32_t len )
{
	uint16_t server_version = 0;
	u_char* org_data = data;
	uint16_t session_id_len = 0;

	if( data[0] != 3 || data[1] > 1) return NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	if( len < SSL3_SERVER_HELLO_MIN_LEN ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

	/* Server Version */
	server_version = MAKE_UINT16( data[0], data[1] );
	if( sess->version == 0 || server_version < sess->version )
	{
		ssls_set_session_version( sess, server_version );
	}
	data+= 2;

	/* ServerRandom */
	_ASSERT_STATIC( sizeof(sess->server_random) == 32 );

	memcpy( sess->server_random, data, sizeof( sess->server_random ) );
	data+= 32;


	/* session ID */
	_ASSERT_STATIC( sizeof(sess->session_id) == 32 );
	session_id_len = data[0];
	data++;

	if( session_id_len > 0 )
	{
		if ( session_id_len != 32 ) return NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );

		if( !IS_ENOUGH_LENGTH( org_data, len, data, session_id_len ) ) 
		{
			return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}

		if( sess->flags & SSF_CLIENT_SESSION_ID_SET 
			&& memcmp( sess->session_id, data, session_id_len ) == 0 )
		{
			int rc = ssls_lookup_session( sess );
			if( NM_IS_FAILED( rc ) ) return rc;
		}
		else
		{
			sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
			memcpy( sess->session_id, data, session_id_len );
		}

		data += session_id_len;
	}

	/* Cipher Suite and Compression */
	if( !IS_ENOUGH_LENGTH( org_data, len, data, 3 ) ) 
	{
		return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	}

	sess->cipher_suite = MAKE_UINT16( data[0], data[1] );
	sess->compression_method = data[2];

	if( sess->flags & SSF_CLIENT_SESSION_ID_SET )
	{
		int rc = ssls_generate_keys( sess );
		if( NM_IS_FAILED( rc ) ) return rc;
	}

	return DSSL_RC_OK;
}


/* First client_hello is a special case, because of SSL v2 compatibility */
int ssl_decode_first_client_hello( DSSL_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_RC_OK;
	
	if( data[0] & 0x80 && len >= 3 && data[2] == SSL2_MT_CLIENT_HELLO )
	{
		rc = ssl2_decode_client_hello( sess, data, len, processed );
	}
	else if( data[0] == SSL3_RT_HANDSHAKE && len > 6 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_CLIENT_HELLO )
	{
		uint32_t recLen = 0;
		u_char* org_data;

		data += SSL3_HEADER_LEN;
		recLen = (((int32_t)data[1]) << 16) | (((int32_t)data[2]) << 8) | data[3];
		org_data = data;

		data += SSL3_HANDSHAKE_HEADER_LEN;
		len -= SSL3_HANDSHAKE_HEADER_LEN;
		
		rc = ssl3_decode_client_hello( sess, data, recLen );
		if( rc == DSSL_RC_OK )
		{
			*processed = recLen + SSL3_HANDSHAKE_HEADER_LEN + SSL3_HEADER_LEN;
			ssl3_init_handshake_digests( sess );
			ssl3_update_handshake_digests( sess, org_data, recLen + SSL3_HANDSHAKE_HEADER_LEN );
		}
	}
	else
	{
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	return rc;
}


int ssl_detect_client_hello_version( u_char* data, uint32_t len, uint16_t* ver )
{
	int rc = DSSL_RC_OK;

	_ASSERT( ver != NULL );
	_ASSERT( data != NULL );

	/* SSL v2 header can be sent even by never clients */
	if( data[0] & 0x80 && len >= 3 && data[2] == SSL2_MT_CLIENT_HELLO )
	{
		*ver = MAKE_UINT16( data[3], data[4] );
	}
	else if ( data[0] == SSL3_RT_HANDSHAKE && len > 11 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_CLIENT_HELLO )
	{
		uint16_t client_hello_ver = MAKE_UINT16( data[9], data[10] );
		*ver = MAKE_UINT16( data[1], data[2] );

		if( *ver != client_hello_ver ) rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
	}
	else
	{
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	return rc;
}


int ssl_detect_server_hello_version( u_char* data, uint32_t len, uint16_t* ver )
{
	int rc = DSSL_RC_OK;

	_ASSERT( ver != NULL );
	_ASSERT( data != NULL );
	
	if( data[0] & 0x80 && len >= SSL20_SERVER_HELLO_MIN_LEN && data[2] == SSL2_MT_SERVER_HELLO )
	{
		*ver = MAKE_UINT16( data[3], data[4] );
	}
	else if( data[0] == SSL3_RT_HANDSHAKE && len > 11 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_SERVER_HELLO )
	{
		uint16_t sever_hello_ver = MAKE_UINT16( data[9], data[10] );
		*ver = MAKE_UINT16( data[1], data[2] );

		if( *ver != sever_hello_ver ) rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
	}
	else
	{
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	return rc;
}


/* ========= ClientKeyExchange ========= */
int ssl3_decode_client_key_exchange( DSSL_Session* sess, u_char* data, uint32_t len )
{
	EVP_PKEY *pk = NULL;
	u_char* org_data = data;
	uint32_t org_len = len;
	int pms_len = 0;
	int rc = DSSL_RC_OK;

	if( sess->version < SSL3_VERSION || sess->version > TLS1_VERSION )
	{
		return NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
	}

	pk = ssls_get_session_private_key( sess );
	if(!pk) return NM_ERROR( DSSL_E_SSL_SERVER_KEY_UNKNOWN );
	if(pk->type != EVP_PKEY_RSA) return NM_ERROR( DSSL_E_SSL_CANT_DECRYPT );

	/* 
	TLS is different as it sends the record length, while SSL3 implementaions don't
	(due to a bug in Netscape implementation)
	*/
	if( sess->version > SSL3_VERSION )
	{
		uint16_t recLen = 0;
		if( !IS_ENOUGH_LENGTH( org_data, org_len, data, 2 ) ) 
		{
			return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}

		recLen = MAKE_UINT16( data[0], data[1] );
		if( len != (uint32_t)recLen + 2 )
		{
			/*TODO: set an option to tolerate this bug?*/
			return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
		}

		/* advance */
		data += len - recLen;
		len = recLen;
	}

	if( !IS_ENOUGH_LENGTH( org_data, org_len, data, SSL_MAX_MASTER_KEY_LENGTH ) )
	{
		return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );
	}

	pms_len = RSA_private_decrypt( len, data, sess->PMS, pk->pkey.rsa, RSA_PKCS1_PADDING );

	if( pms_len != SSL_MAX_MASTER_KEY_LENGTH )
	{
		return NM_ERROR( DSSL_E_SSL_CORRUPTED_PMS );
	}

	if( MAKE_UINT16( sess->PMS[0], sess->PMS[1] ) != sess->client_version )
	{
		return NM_ERROR( DSSL_E_SSL_PMS_VERSION_ROLLBACK );
	}

	rc = ssls_decode_master_secret( sess );
	OPENSSL_cleanse(sess->PMS, sizeof(sess->PMS) );

	if( rc != DSSL_RC_OK ) return rc;

	rc = ssls_generate_keys( sess );
	if( rc == DSSL_RC_OK )
	{
		ssls_store_session( sess );
	}
	return rc;
}


static int ssl3_decode_dummy( DSSL_Session* sess, u_char* data, uint32_t len )
{
	UNUSED_PARAM( sess );
	UNUSED_PARAM( data );
	UNUSED_PARAM( len );

	return DSSL_RC_OK;
}


/* ========== Finished, handshake digest routines ========== */
static void ssl3_init_handshake_digests( DSSL_Session* sess )
{
	EVP_DigestInit_ex( &sess->handshake_digest_md5, EVP_md5(), NULL );
	EVP_DigestInit_ex( &sess->handshake_digest_sha, EVP_sha1(), NULL );
}


static void ssl3_update_handshake_digests( DSSL_Session* sess, u_char* data, uint32_t len )
{
	EVP_DigestUpdate( &sess->handshake_digest_md5, data, len );
	EVP_DigestUpdate( &sess->handshake_digest_sha, data, len );

}


/* ========== Handshake decoding function ========== */
int ssl3_decode_handshake_record( dssl_decoder_stack* stack, NM_PacketDir dir,
								 u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = DSSL_E_UNSPECIFIED_ERROR;
	uint32_t recLen = 0;
	u_char hs_type = 0;
	u_char* org_data = data;
	DSSL_Session* sess = stack->sess;
	_ASSERT( processed != NULL );

	if( sess->version == 0 )
	{
		return ssl_decode_first_client_hello( sess, data, len, processed );
	}

	if( len < SSL3_HANDSHAKE_HEADER_LEN ) return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

	recLen = (((int32_t)data[1]) << 16) | (((int32_t)data[2]) << 8) | data[3];
	hs_type = data[0];

	data += SSL3_HANDSHAKE_HEADER_LEN;
	len -= SSL3_HANDSHAKE_HEADER_LEN;

	if( len < recLen )return NM_ERROR( DSSL_E_SSL_INVALID_RECORD_LENGTH );

#ifdef NM_TRACE_SSL_HANDSHAKE
	DEBUG_TRACE2( "Decoding SSL handshake: type %d, len: %d...", (int) hs_type, (int) recLen );
#endif

	switch( hs_type )
	{
	case SSL3_MT_HELLO_REQUEST:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CLIENT_HELLO:
		rc = ssl3_decode_client_hello( sess, data, recLen );
		break;

	case SSL3_MT_SERVER_HELLO:
		stack->state = SS_SeenServerHello;
		rc = ssl3_decode_server_hello( sess, data, recLen );
		break;

	case SSL3_MT_CERTIFICATE:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_SERVER_DONE:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CLIENT_KEY_EXCHANGE:
		rc = ssl3_decode_client_key_exchange( sess, data, recLen );
		break;

	case SSL3_MT_FINISHED:
		rc = (*sess->decode_finished_proc)( sess, dir, data, recLen );
		if( rc == DSSL_RC_OK ) stack->state = SS_Established;
		break;

	case SSL3_MT_SERVER_KEY_EXCHANGE:
		/*at this point it is clear that the session is not decryptable due to ephemeral keys usage.*/
		rc = NM_ERROR( DSSL_E_SSL_CANT_DECRYPT );
		break;

	case SSL3_MT_CERTIFICATE_REQUEST:
		/* TODO: track CertificateRequest- client certificate / certificate verify */
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CERTIFICATE_VERIFY:
		/* TODO: track CertificateRequest- client certificate / certificate verify */
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	default:
		rc = NM_ERROR( DSSL_E_SSL_PROTOCOL_ERROR );
		break;
	}

	if( rc == DSSL_RC_OK )
	{
		*processed = recLen + SSL3_HANDSHAKE_HEADER_LEN;

		if( hs_type == SSL3_MT_CLIENT_HELLO ) 
		{
			ssl3_init_handshake_digests( sess );
		}

		if( hs_type != SSL3_MT_HELLO_REQUEST )
		{
			ssl3_update_handshake_digests( sess, org_data, *processed );
		}
	}

#ifdef NM_TRACE_SSL_HANDSHAKE
	if( rc == DSSL_RC_OK )
	{
		DEBUG_TRACE0( "OK\n" );
	}
	else
	{
		DEBUG_TRACE1( "Error! (%d)\n", (int)rc );
	}
#endif

	return rc;
}

