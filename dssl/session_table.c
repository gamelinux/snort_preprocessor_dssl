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
#include "fnv_hash.h"

/* Calculates a hash key for a (ip1, port1)<->(ip2, port2) tcp session */
static uint32_t getTcpSessionHash( uint32_t ip1, uint16_t port1, uint32_t ip2, uint16_t port2 )
{
	uint32_t hash;

	if( ip1 < ip2 )
	{
		hash = fnv_32_buf( &ip1, sizeof(ip1), FNV1_32_INIT );
		hash = fnv_32_buf( &port1, sizeof(port1), hash );
		hash = fnv_32_buf( &ip2, sizeof(ip2), hash );
		hash = fnv_32_buf( &port2, sizeof(port2), hash );
	}
	else 
	{
		hash = fnv_32_buf( &ip2, sizeof(ip2), FNV1_32_INIT );
		hash = fnv_32_buf( &port2, sizeof(port2), hash );
		hash = fnv_32_buf( &ip1, sizeof(ip1), hash );
		hash = fnv_32_buf( &port1, sizeof(port1), hash );
	}
	return hash;
}


/* Calculates a TcpSession hash key from packet's src and dest {ip, port} pairs */
static uint32_t getPktSessionHash( DSSL_Pkt* pkt )
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( pkt );
	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );

	/* use the smaller ip number as "ip1"
		(if source and dest IPs are the same,
		port1 is the smallest port)
	*/
	
	if( INADDR_IP( pkt->ip_header->ip_src ) < INADDR_IP( pkt->ip_header->ip_dst ) )
	{
		ip1 = INADDR_IP( pkt->ip_header->ip_src );
		ip2 = INADDR_IP( pkt->ip_header->ip_dst );
		port1 = PKT_TCP_SPORT( pkt );
		port2 = PKT_TCP_DPORT( pkt );
	}
	else if( INADDR_IP( pkt->ip_header->ip_src ) > INADDR_IP( pkt->ip_header->ip_dst ) )
	{
		ip2 = INADDR_IP( pkt->ip_header->ip_src );
		ip1 = INADDR_IP( pkt->ip_header->ip_dst );
		port2 = PKT_TCP_SPORT( pkt );
		port1 = PKT_TCP_DPORT( pkt );
	}
	else
	{
		ip1 = ip2 = INADDR_IP( pkt->ip_header->ip_src );

		if( PKT_TCP_SPORT( pkt ) < PKT_TCP_DPORT( pkt ) )
		{
			port1 = PKT_TCP_SPORT( pkt );
			port2 = PKT_TCP_DPORT( pkt );
		}
		else
		{
			port2 = PKT_TCP_SPORT( pkt );
			port1 = PKT_TCP_DPORT( pkt );
		}
	}

	return getTcpSessionHash( ip1, port1, ip2, port2 );
}


/* Calculate TcpSession's hash key */
static uint32_t getSessionHash( TcpSession* sess )
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( sess );

	if( sess->clientStream.ip_addr < sess->serverStream.ip_addr )
	{
		ip1 = sess->clientStream.ip_addr;
		ip2 = sess->serverStream.ip_addr;

		port1 = sess->clientStream.port;
		port2 = sess->serverStream.port;
	}
	else if( sess->clientStream.ip_addr > sess->serverStream.ip_addr )
	{
		ip2 = sess->clientStream.ip_addr;
		ip1 = sess->serverStream.ip_addr;

		port2 = sess->clientStream.port;
		port1 = sess->serverStream.port;
	}
	else
	{
		ip1 = ip2 = sess->clientStream.ip_addr;
		
		if( sess->clientStream.port < sess->serverStream.port )
		{
			port1 = sess->clientStream.port;
			port2 = sess->serverStream.port;
		}
		else
		{
			port1 = sess->clientStream.port;
			port2 = sess->serverStream.port;
		}
	}

	return getTcpSessionHash( ip1, port1, ip2, port2 );
}


static TcpSession* _SessionTable_FindSession( dssl_SessionTable* tbl, DSSL_Pkt* pkt )
{
	uint32_t hash;
	TcpSession* sess;

	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );

	/* calculate hash index */
	hash = getPktSessionHash( pkt ) % tbl->tableSize;

	/* find the session in the table */
	sess = tbl->table[hash];
	while( sess && SessionGetPacketDirection( sess, pkt ) == ePacketDirInvalid ) sess = sess->next;

	return sess;
}


static void _SessionTable_addSession( dssl_SessionTable* tbl, TcpSession* sess )
{
	uint32_t hash;
	TcpSession** prevSession;

	_ASSERT( tbl );
	_ASSERT( sess );

	sess->next = NULL;
	hash = getSessionHash( sess ) % tbl->tableSize;

	prevSession = &tbl->table[hash];

	while( (*prevSession) != NULL ) prevSession = &(*prevSession)->next;

	(*prevSession) = sess;
}


static TcpSession* _SessionTable_CreateSession( dssl_SessionTable* tbl, DSSL_Pkt* pkt, NM_SessionType s_type )
{
	TcpSession* sess;

	_ASSERT( tbl );	_ASSERT( pkt );

	if( s_type == eSessionTypeNull )
	{
		_ASSERT( s_type != eSessionTypeNull );
		return NULL;
	}

	sess = (TcpSession*) malloc( sizeof(*sess) );

	/* TODO: handle low memory condition */
	if( sess == NULL ) return NULL;

	if( SessionInit( tbl->env, sess, pkt, s_type ) != DSSL_RC_OK )
	{
		free( sess );
		return NULL;
	}

	if( tbl->env && tbl->env->session_callback )
	{
		tbl->env->session_callback( tbl->env, sess, DSSL_EVENT_NEW_SESSION );
	}

	_SessionTable_addSession( tbl, sess );

	++ tbl->sessionCount;

	return sess;
}


static void SessionTableFreeSession( dssl_SessionTable* tbl, TcpSession* sess )
{
	if( tbl->env && tbl->env->session_callback )
	{
		tbl->env->session_callback( tbl->env, sess, DSSL_EVENT_SESSION_CLOSING );
	}
	SessionFree( sess );
}


static void _SessionTable_DestroySession( dssl_SessionTable* tbl, TcpSession* sess )
{
	uint32_t hash;
	TcpSession** s;
	_ASSERT( tbl ); _ASSERT( sess );

	hash = getSessionHash( sess ) % tbl->tableSize;
	s = &tbl->table[hash];

	while( (*s) &&  (*s) != sess ) 
		s = &(*s)->next;

	if( *s )
	{
		(*s) = (*s)->next;
		SessionTableFreeSession( tbl, sess );
		-- tbl->sessionCount;
	}
}


static void _SessionTable_RemoveAll( dssl_SessionTable* tbl )
{
	int i;
	for( i=0; i < tbl->tableSize; ++i )
	{
		TcpSession* s = tbl->table[i];
		while( s )
		{
			TcpSession* ss = s;
			s = s->next;
			SessionTableFreeSession( tbl, ss );
		}
	}

	memset( tbl->table, 0, sizeof(tbl->table[0])*tbl->tableSize );
	tbl->sessionCount = 0;
}


/* dssl_SessionTable "constructor" routine */
dssl_SessionTable* CreateSessionTable( int tableSize )
{
	dssl_SessionTable* tbl;

	_ASSERT( tableSize > 0 );

	tbl = (dssl_SessionTable*) malloc( sizeof(dssl_SessionTable) );
	memset( tbl, 0, sizeof(*tbl) );

	tbl->FindSession = _SessionTable_FindSession;
	tbl->CreateSession = _SessionTable_CreateSession;
	tbl->DestroySession = _SessionTable_DestroySession;
	tbl->RemoveAll = _SessionTable_RemoveAll;

	tbl->table = (TcpSession**) malloc( sizeof(tbl->table[0])*tableSize );
	memset( tbl->table, 0, sizeof(tbl->table[0])*tableSize );

	tbl->tableSize = tableSize;
	return tbl;
}


void DestroySessionTable( dssl_SessionTable* tbl )
{
	tbl->RemoveAll( tbl );
	free( tbl->table );
	free( tbl );
}
