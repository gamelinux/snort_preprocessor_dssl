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
#ifndef __DSSL_STREAM_H__
#define __DSSL_STREAM_H__

#include "packet.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum _TcpStreamState
{
	tcpClosed,
	tcpListen,
	tcpSynSent,
	tcpSynReceived,
	tcpEstablished,
	tcpFinWait1,
	tcpFinWait2,
	tcpCloseWait,
	tcpClosing,
	tcpLastACK,
	tcpTimeWait
} TcpStreamState;


typedef enum _TcpStateChangeAction
{
	stchNoAction,
	stchCheckACK,
	stchCheckFlags
} TcpStateChangeAction;

struct _TcpStream
{
	uint32_t		ip_addr;
	uint16_t		port;
    DSSL_Pkt*			pktHead;
    DSSL_Pkt*			pktTail;
    DSSL_Pkt*			pktLastReassembled;
	uint32_t		nextSeqExpected;
	TcpStreamState	state;

	/* state change info generated from previous packet analysis */
	uint32_t				stch_ack;
	TcpStateChangeAction	stch_action; /* STCH_ACTION_ACK or STCH_ACTION_FLAGS */
	TcpStreamState			stch_state;
	uint8_t					stch_flags;

	TcpSession*				session;
};


/* Initialization / destruction */
void StreamInit( TcpStream* stream, TcpSession* sess, uint32_t ip, uint16_t port, TcpStreamState initState );
void StreamFreeData( TcpStream* stream );

/* Main packet processing function */

int StreamProcessPacket( TcpStream* stream, DSSL_Pkt* pkt );


/* TCP state change management for the next packet in the stream */
void StreamStateChangeOnACK( TcpStream* stream, TcpStreamState state, uint32_t ack );
void StreamStateChangeOnFlags( TcpStream* stream, TcpStreamState state, uint8_t flags );
void StreamCheckStateChange( TcpStream* stream, DSSL_Pkt* pkt );

#ifdef NM_TRACE_TCP_STREAMS
	const char* GetStreamStateName( TcpStreamState state );

	#define SET_STREAM_STATE( stream, st ) { DEBUG_TRACE3( "\nstream: %p - TCP State change: %s -> %s", \
				stream, GetStreamStateName( stream->state ), GetStreamStateName( st ) ); \
				stream->state = st; }
#else
	#define SET_STREAM_STATE( stream, st ) stream->state = st;
#endif

#ifdef  __cplusplus
}
#endif

#endif
