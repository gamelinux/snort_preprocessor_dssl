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
#ifndef __DSSL_SSL_CTX_H__
#define __DSSL_SSL_CTX_H__

#ifdef  __cplusplus
extern "C" {
#endif

/* DSSL_ServerInfo - maps server ip:port to SSL certificate, RSA private key file 
	and key file password */

struct DSSL_ServerInfo_
{
	struct in_addr	server_ip;
	uint16_t		port;
	char*			keyfile;
	char*			certfile;
	char*			pwd;

	EVP_PKEY*		pkey;
};


typedef struct _DSSL_Env
{
	DSSL_ServerInfo**		servers;
	int						server_count;

	dssl_SessionKeyTable*	session_cache;

#ifndef NM_MULTI_THREADED_SSL
	u_char			decomp_buffer[16*1024];
#else
	#error "Multi-threading is not implemented for DSSL_Env"
#endif

} DSSL_Env;


DSSL_Env* DSSL_EnvCreate( int session_cache_size, uint32_t cache_timeout_interval );
void DSSL_EnvDestroy( DSSL_Env* env );


/* SSL Server info */
int DSSL_EnvSetServerInfo( DSSL_Env* env, struct in_addr* ip_address, uint16_t port, 
			const char* certfile, const char* keyfile, const char* password );

DSSL_ServerInfo* DSSL_EnvFindServerInfo( DSSL_Env* env, struct in_addr* server_ip, uint16_t port );

/* Session mgmt */
DSSL_Session* DSSL_EnvCreateSession( DSSL_Env* env, struct in_addr* server_ip, uint16_t port );
void DSSL_EnvOnSessionClosing( DSSL_Env* env, DSSL_Session* sess );


/*========= DSSL_ServerInfo =========*/
/* Init a DSSL_ServerInfo structure */

int DSSL_ServerInfoInit( DSSL_ServerInfo* si );

/* Free a DSSL_ServerInfo structure */
void DSSL_ServerInfoFree( DSSL_ServerInfo* si );

#ifdef  __cplusplus
}
#endif

#endif /*__DSSL_SSL_CTX_H__*/
