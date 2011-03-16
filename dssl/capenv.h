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
#ifndef __DSSL_CAPENV_H__
#define __DSSL_CAPENV_H__

#include "session_table.h"
#include "ssl_ctx.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CapEnv_;

#define DSSL_EVENT_NEW_SESSION		0
#define DSSL_EVENT_SESSION_CLOSING	1

typedef void (*CapEnvSessionCallback)( struct CapEnv_* env, TcpSession* sess, char event );

/* Packet capture environment */
struct CapEnv_
{
	pcap_t*				pcap_adapter;
    pcap_handler        handler;
	
	dssl_SessionTable*		sessions;
	DSSL_Env*			ssl_env;

/*  
	ForReassemble: return on of NM_REASSEMBLE_XXX constants or 0 if
	the paket should be ignored.
	Note: pkt->tcp_header must be initialized before calling this function!
*/
	NM_SessionType (*ForReassemble)( struct CapEnv_* env, DSSL_Pkt* pkt );
	
	/* called when a new session is created before it is added to the session table */
	CapEnvSessionCallback	session_callback;

	void* env_user_data;

};


CapEnv* CapEnvCreate( pcap_t* adapter, int sessionTableSize, uint32_t cache_timeout_interval );
void CapEnvDestroy( CapEnv* env );

/* TODO: add the default session data callback that will be used when no OnNewSession callback is set */
void CapEnvSetSessionCallback( CapEnv* env, CapEnvSessionCallback callback, void* user_data );

void* CapEnvGetUserData( CapEnv* env );

#ifndef DSSL_NO_PCAP
/* run pcap_loop on environment's pcap adapter; return value is the same as for pcap_loop call */
int CapEnvCapture( CapEnv* env );
#endif

/* Single-server version of setting up the DSSL_ServerInfo table struct for given CapEnv. 
	Returns 0 if successful, non-zero error code (DSSL_E_OUT_OF_MEMORY) otherwise. */
int CapEnvSetSSL_ServerInfo( CapEnv* env, struct in_addr* ip_address, uint16_t port, 
					  const char* certfile, const char* keyfile, const char* password );

DSSL_ServerInfo* CapEnvFindDSSL_ServerInfo( CapEnv* env, struct in_addr* server_ip, uint16_t server_port );

/* Packet processing routine*/
void CapEnvProcessPacket( CapEnv* env, DSSL_Pkt* pkt );

#ifdef  __cplusplus
}
#endif

#endif
