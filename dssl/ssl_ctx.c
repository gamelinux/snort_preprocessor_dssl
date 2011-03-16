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
#include "ssl_ctx.h"
#include "ssl_session.h"
#include "ssl_sessionkey_table.h"

/* Free an array of DSSL_ServerInfo structures */

void DSSL_ServerInfoFree( DSSL_ServerInfo* si )
{
	if( si == NULL ) return;

	free( si->certfile );
	free( si->keyfile );
	free( si->pwd );

	if( si->pkey != NULL )
	{
		EVP_PKEY_free( si->pkey );
		si->pkey = NULL;
	}

	free( si );
}


static void DSSL_ServerInfoFreeArray( DSSL_ServerInfo** si, int size )
{
	int i;
	_ASSERT( si );
	_ASSERT( size > 0 );

	for( i = 0; i < size; i++ ) 
	{
		DSSL_ServerInfoFree( si[i] );
	}

	free( si );
}


/* simple password callback function to use with openssl certificate / private key API */
static int password_cb_direct( char *buf, int size, int rwflag, void *userdata )
{
	char* pwd = (char*) userdata;
	int len = (int) strlen( pwd );

	rwflag;

	strncpy( buf, pwd, size );
	return len;
}


static int ServerInfo_LoadPrivateKey( DSSL_ServerInfo* si )
{
	FILE* f = NULL;
	int rc = DSSL_RC_OK;

	f = fopen( si->keyfile, "r" );

	if( !f ) return NM_ERROR( DSSL_E_SSL_LOAD_PRIVATE_KEY );

	if( rc == DSSL_RC_OK && PEM_read_PrivateKey( f, &si->pkey, password_cb_direct, si->pwd ) == NULL )
	{
		rc = NM_ERROR( DSSL_E_SSL_LOAD_PRIVATE_KEY );
	}

	fclose( f );

	return rc;
}


int DSSL_ServerInfoInit( DSSL_ServerInfo* si )
{
	return ServerInfo_LoadPrivateKey( si );
}


DSSL_Session* DSSL_EnvCreateSession( DSSL_Env* env, struct in_addr* server_ip, uint16_t port )
{
	DSSL_ServerInfo* si = DSSL_EnvFindServerInfo( env, server_ip, port );
	DSSL_Session* sess = NULL;

	if( !si ) return NULL;

	sess = malloc( sizeof( DSSL_Session) );

	DSSL_SessionInit( env, sess, si );

	return sess;
}


void DSSL_EnvOnSessionClosing( DSSL_Env* env, DSSL_Session* s )
{
	_ASSERT( env );
	_ASSERT( s );

	if( env->session_cache )
	{
		dssl_SessionKT_Release( env->session_cache, s->session_id );
	}
}


DSSL_Env* DSSL_EnvCreate( int session_cache_size, uint32_t cache_timeout_interval )
{
	DSSL_Env* env = (DSSL_Env*) malloc( sizeof( DSSL_Env ) );
	if( !env ) return NULL;

	memset( env, 0, sizeof( *env ) );

	env->session_cache = dssl_SessionKT_Create( session_cache_size, cache_timeout_interval );
	return env;
}


void DSSL_EnvDestroy( DSSL_Env* env )
{
	if( env->servers ) 
	{
		_ASSERT( env->server_count > 0 );
		DSSL_ServerInfoFreeArray( env->servers, env->server_count );
		env->server_count = 0;
		env->servers = NULL;
	}

	if( env->session_cache )
	{
		dssl_SessionKT_Destroy( env->session_cache );
	}

	free( env );
}


int DSSL_EnvAddServer( DSSL_Env* env, DSSL_ServerInfo* server )
{
	DSSL_ServerInfo** new_servers = NULL;
	new_servers = realloc( env->servers, (env->server_count + 1)*sizeof(*env->servers) );

	if( new_servers == NULL ) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	new_servers[env->server_count] = server;
	env->servers = new_servers;
	env->server_count++;

	return DSSL_RC_OK;
}

int DSSL_EnvSetServerInfo( DSSL_Env* env, struct in_addr* ip_address, uint16_t port, 
			const char* certfile, const char* keyfile, const char* password )
{
	DSSL_ServerInfo* server = NULL;
	int rc = DSSL_RC_OK;

	server = (DSSL_ServerInfo*) calloc( 1, sizeof( DSSL_ServerInfo ) );
	
	if( !server ) return NM_ERROR( DSSL_E_OUT_OF_MEMORY );

	server->certfile = strdup( certfile );
	server->keyfile = strdup( keyfile );
	server->pwd = strdup( password );
	memcpy( &server->server_ip,  ip_address, sizeof(server->server_ip) ) ;
	server->port = port;

	rc = DSSL_ServerInfoInit( server );
	if( rc != DSSL_RC_OK ) 
	{
		DSSL_ServerInfoFree( server );
		return rc;
	}

	rc = DSSL_EnvAddServer( env, server );

	if( rc != DSSL_RC_OK )
	{
		DSSL_ServerInfoFree( server );
	}

	return DSSL_RC_OK;
}


/* find DSSL_ServerInfo in a table by ip:port */
DSSL_ServerInfo* DSSL_EnvFindServerInfo( DSSL_Env* env, struct in_addr* ip_address, uint16_t port )
{
	int i;
	_ASSERT( ip_address );

	for( i = 0; i < env->server_count; i++ )
	{
		DSSL_ServerInfo* si = env->servers[i];

		if( INADDR_IP( si->server_ip ) == INADDR_IP( *ip_address ) &&
			port == si->port ) return si;
	}

	return NULL;
}
