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
#include "capenv.h"
#include "decode.h"
#include "ssl_ctx.h"

/* TODO: make it configurable */
NM_SessionType _CaptureEnv_ForReassemble( struct CapEnv_* env, struct DSSL_Pkt_* pkt )
{
	uint16_t port = PKT_TCP_DPORT( pkt );

	/* check if the destination ip:port is in the SSL server list */
	if( CapEnvFindDSSL_ServerInfo( env, &pkt->ip_header->ip_dst, port ) )
	{
		return eSessionTypeSSL;
	}

	/* TODO: apply config settings*/
	return eSessionTypeTcp;
}


CapEnv* CapEnvCreate( pcap_t* adapter, int sessionTableSize, uint32_t cache_timeout_interval )
{
	CapEnv* env;

	if( cache_timeout_interval == 0 ) cache_timeout_interval = 60*60;

	_ASSERT( cache_timeout_interval > 0 );

	env = (CapEnv*) malloc( sizeof(CapEnv) );
	memset( env, 0, sizeof(*env) );

	env->pcap_adapter = adapter;

#ifndef DSSL_NO_PCAP
	if( env->pcap_adapter != NULL )
	{
		env->handler = GetPcapHandler( env->pcap_adapter );
	}
#else
	_ASSERT( env->pcap_adapter == NULL );
#endif

	env->ForReassemble = _CaptureEnv_ForReassemble;
    
	env->sessions = CreateSessionTable( sessionTableSize );
	env->sessions->env = env;
	env->session_callback = NULL;
	env->env_user_data = NULL;

	env->ssl_env = DSSL_EnvCreate( sessionTableSize, cache_timeout_interval );

	return env;
}


void CapEnvDestroy( CapEnv* env )
{
	DestroySessionTable( env->sessions );

	if( env->ssl_env ) 
	{
		DSSL_EnvDestroy( env->ssl_env );
		env->ssl_env = NULL;
	}

	free( env );
}

#ifndef DSSL_NO_PCAP
/* run pcap_loop on environment's pcap adapter */
int CapEnvCapture( CapEnv* env )
{
	if( env->pcap_adapter == NULL ) return -1;
    return pcap_loop( env->pcap_adapter, -1, env->handler, (u_char*) env );
}
#endif

/* Packet processing routine*/
void CapEnvProcessPacket( CapEnv* env, DSSL_Pkt* pkt )
{
	NM_SessionType s_type = env->ForReassemble( env, pkt );

	/* Check if this packet is to be reassembled / decoded*/
	if( s_type == eSessionTypeNull ) return;

	/* Lookup an existing session */
	pkt->session = env->sessions->FindSession( env->sessions, pkt );

	/* No session found, try creaing a new one */
	if( !pkt->session ) 
	{
		pkt->session = env->sessions->CreateSession( env->sessions, pkt, s_type );
	}
	if( pkt->session ) SessionProcessPacket( env, pkt );
}


int CapEnvSetSSL_ServerInfo( CapEnv* env, struct in_addr* ip_address, uint16_t port, 
			const char* certfile, const char* keyfile, const char* password )
{
	if( env->ssl_env == NULL ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	return DSSL_EnvSetServerInfo( env->ssl_env, ip_address, port, certfile, keyfile, password );
}


void CapEnvSetSessionCallback( CapEnv* env, CapEnvSessionCallback callback, void* user_data )
{
	_ASSERT( env );
	
	env->session_callback = callback;
	env->env_user_data = user_data;
}

void* CapEnvGetUserData( CapEnv* env )
{
	_ASSERT( env );
	return env->env_user_data;
}


DSSL_ServerInfo* CapEnvFindDSSL_ServerInfo( CapEnv* env, 
		struct in_addr* server_ip, uint16_t server_port )
{
	if( env->ssl_env ) 
		return DSSL_EnvFindServerInfo( env->ssl_env, server_ip, server_port );
	else
		return NULL;
}
