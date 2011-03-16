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
#ifndef __DSSL_SESSION_H__
#define __DSSL_SESSION_H__

#include "dssl_defs.h"
#include "stream.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct _TcpSession
{
	NM_SessionType		type;
	TcpStream			clientStream;
	TcpStream			serverStream;
	struct _TcpSession*	next;
	NM_PacketDir		lastPacketDirection;
	int					closing;
	DataCallbackProc	data_callback;
	ErrorCallbackProc	error_callback;
	void*				user_data;
	
	/* reassembled packet callback */
	int (*OnNewPacket)( struct _TcpStream* stream, DSSL_Pkt* pkt );
	struct DSSL_Session_*	ssl_session;
};

int SessionInit( CapEnv* env, TcpSession* s, DSSL_Pkt* pkt, NM_SessionType s_type );
void SessionFree( TcpSession* s );

NM_PacketDir SessionGetPacketDirection( TcpSession* sess, DSSL_Pkt* pkt );

void SessionProcessPacket( struct CapEnv_* env, DSSL_Pkt* pkt );

void SessionSetCallback( TcpSession* sess, DataCallbackProc data_callback, 
			ErrorCallbackProc error_callback, void* user_data );

void SessionSetUserData( TcpSession* sess, void* data );
void* SessionGetUserData( TcpSession* sess );

#ifdef  __cplusplus
}
#endif

#endif
