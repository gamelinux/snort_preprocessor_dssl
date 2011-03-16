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
#include "ssl_session.h"

#define SES_PACKET_DIR_MASK			3
#define SES_ACTION_CLOSE			8

/* Local prototypes */
static int OnNewPlainTextPacket( TcpStream* stream, DSSL_Pkt* pkt );
static int OnNewSSLPacket( TcpStream* stream, DSSL_Pkt* pkt );

NM_PacketDir SessionGetPacketDirection( TcpSession* sess, DSSL_Pkt* pkt)
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( sess );
	_ASSERT( pkt );

	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );

	ip1 = INADDR_IP( pkt->ip_header->ip_src );
	ip2 = INADDR_IP( pkt->ip_header->ip_dst );

	port1 = PKT_TCP_SPORT( pkt );
	port2 = PKT_TCP_DPORT( pkt );

	if( sess->clientStream.ip_addr == ip1 && sess->serverStream.ip_addr == ip2 && 
		sess->clientStream.port == port1 && sess->serverStream.port == port2 )
	{
		return ePacketDirFromClient;
	} 
	else if( sess->clientStream.ip_addr == ip2 && sess->serverStream.ip_addr == ip1 &&
			sess->clientStream.port == port2 && sess->serverStream.port == port1 )
	{
		return ePacketDirFromServer;
	}
	else
	{
		return ePacketDirInvalid;
	}
}


int SessionInit( CapEnv* env, TcpSession* sess, DSSL_Pkt* pkt, NM_SessionType s_type )
{
	int is_server = 0;

	memset( sess, 0, sizeof(*sess) );
	sess->type = s_type;

	if( s_type != eSessionTypeSSL && s_type != eSessionTypeTcp ) return NM_ERROR( DSSL_E_INVALID_PARAMETER );

	switch( pkt->tcp_header->th_flags & ~(TH_ECNECHO | TH_CWR) )
	{
	case TH_SYN:
		StreamInit( &sess->clientStream, sess,
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ), tcpSynSent );
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ), tcpListen );

		is_server = 0;
		break;

	case TH_SYN | TH_ACK:
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ), tcpSynReceived );
		StreamInit( &sess->clientStream, sess,
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ), tcpSynSent );

		is_server = 1;
		break;

	default:
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ), tcpEstablished );
		StreamInit( &sess->clientStream, sess, 
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ), tcpEstablished );

		/* 
		This connection has already been established. Can't reassemble the SSL session from the middle,
		hence ignore this session.
		*/
		if( sess->type == eSessionTypeSSL ) sess->type = eSessionTypeNull;
		break;
	}

	/* set up the decoders */
	switch( sess->type )
	{
	case eSessionTypeTcp:
		sess->OnNewPacket = OnNewPlainTextPacket;
		break;

	case eSessionTypeSSL:
		/* create SSL session */
		if( env->ssl_env != NULL ) 
		{
			sess->ssl_session = DSSL_EnvCreateSession( env->ssl_env, 
					&pkt->ip_header->ip_dst, PKT_TCP_DPORT( pkt ) );
		}
		else
		{
			sess->ssl_session = NULL;
		}

		/* set packet callback */
		if( sess->ssl_session != NULL )
		{
			sess->OnNewPacket = OnNewSSLPacket;
			DSSL_SessionSetCallback( sess->ssl_session, sess->data_callback, 
					sess->error_callback, sess->user_data );
		}
		else
		{
			sess->type = eSessionTypeNull; /* TODO: report error? */
		}
		break;

	case eSessionTypeNull:
		break;

	default:
		_ASSERT( FALSE );
		break;
	}

	return DSSL_RC_OK;
}

/* can be called multiple times; preserve state */
static void SessionDeInit( TcpSession* sess )
{
	_ASSERT( sess );

	if( sess->ssl_session )
	{
		DSSL_SessionDeInit( sess->ssl_session );
		free( sess->ssl_session );
		sess->ssl_session = NULL;
	}

	StreamFreeData( &sess->clientStream );
	StreamFreeData( &sess->serverStream );

	sess->type = eSessionTypeNull;
}


void SessionFree( TcpSession* sess )
{
	SessionDeInit( sess );
	free( sess );
}


static uint32_t PreProcessPacket( DSSL_Pkt* pkt )
{
	int dir;
	TcpStream* sender, *receiver;
	int th_flags;
	uint32_t th_seq;
	TcpSession* sess = pkt->session;
	uint32_t rc = 0;

	dir = SessionGetPacketDirection( sess, pkt );
	if( dir == ePacketDirInvalid )
	{
		_ASSERT( dir != ePacketDirInvalid );
		return SES_ACTION_CLOSE;
	}

	rc = dir;

	if( dir == ePacketDirFromClient )
	{
		sender = &sess->clientStream;
		receiver = &sess->serverStream;
	}
	else if( dir == ePacketDirFromServer )
	{
		sender = &sess->serverStream;
		receiver = &sess->clientStream;
	}
	else
	{
		_ASSERT( FALSE );
		return SES_ACTION_CLOSE;
	}

	StreamCheckStateChange( sender, pkt );

	th_flags = pkt->tcp_header->th_flags;
	th_seq = ntohl( pkt->tcp_header->th_seq );

	if( th_flags & TH_RST ) rc |= SES_ACTION_CLOSE;

	switch( receiver->state )
	{
	case tcpListen:
		if( th_flags & TH_SYN ) 
		{
			sender->state = tcpSynSent;
		}
		break;

	case tcpSynSent:
		if( th_flags & (TH_SYN | TH_ACK) ) 
		{
			SET_STREAM_STATE( sender, tcpSynReceived ); 
			StreamStateChangeOnFlags( receiver, tcpEstablished, TH_ACK );
		}
		break;

	case tcpSynReceived:
		if( th_flags & TH_ACK ) SET_STREAM_STATE( sender, tcpEstablished ); 
		break;

	case tcpEstablished:
		if( sender->state == tcpSynReceived && th_flags & TH_ACK ) 
		{
			SET_STREAM_STATE( sender, tcpEstablished );
		}

		if( th_flags & TH_FIN )
		{
			SET_STREAM_STATE( sender, tcpFinWait1 );
			StreamStateChangeOnACK( receiver, tcpCloseWait, th_seq );
		}
		break;

	case tcpFinWait1:
		if( th_flags == TH_ACK )
		{
			StreamStateChangeOnFlags( sender, tcpLastACK, TH_FIN );
			SET_STREAM_STATE( receiver, tcpFinWait2 );
		} else if( (th_flags & (TH_FIN | TH_ACK)) == (TH_FIN | TH_ACK) )
		{
			SET_STREAM_STATE( sender, tcpLastACK );
			StreamStateChangeOnACK( receiver, tcpTimeWait, th_seq );
		}
		break;

	case tcpFinWait2:
		if( th_flags & TH_FIN )
		{
			SET_STREAM_STATE( sender, tcpLastACK );
			StreamStateChangeOnACK( receiver, tcpTimeWait, th_seq );
		}
		break;
		
	case tcpCloseWait:
		StreamStateChangeOnFlags( sender, tcpLastACK, TH_FIN );
		break;

	case tcpLastACK:
		if( th_flags & TH_ACK )
		{
			SET_STREAM_STATE( receiver, tcpClosed );
			if( sender->state == tcpTimeWait )
			{
				SET_STREAM_STATE( sender, tcpClosed );
			}
		}
		rc |= SES_ACTION_CLOSE;
		break;

	case tcpClosed:
	case tcpTimeWait:
		rc |= SES_ACTION_CLOSE;
		break;
	}

	return rc;
}

static void SessionOnError( TcpSession* sess, int error_code )
{
	if( sess->error_callback )
	{
		sess->error_callback( sess->user_data, error_code );
	}
}


static int SessionDecodable( TcpSession* sess )
{
	return sess->type != eSessionTypeNull;
}


void SessionProcessPacket( CapEnv* env, DSSL_Pkt* pkt )
{
	uint32_t code;
	TcpStream* stream = NULL;
	int rc = DSSL_RC_OK;
	int dir = 0;

	_ASSERT( pkt );
	_ASSERT( pkt->session );

	if( !SessionDecodable( pkt->session ) ) return;

	code = PreProcessPacket( pkt );
	dir = code & SES_PACKET_DIR_MASK;

	switch( dir )
	{
	case ePacketDirFromClient:
		stream = &pkt->session->clientStream;
		break;
	case ePacketDirFromServer:
		stream = &pkt->session->serverStream;
		break;

	default:
		_ASSERT( FALSE ); /* this packet does not belong to this session? */
		return;
	}

	rc = StreamProcessPacket( stream, pkt );

	if( pkt->session->closing ) code |= SES_ACTION_CLOSE;

	if(  rc != DSSL_RC_OK )
	{
		SessionOnError( pkt->session, rc );
		code |= SES_ACTION_CLOSE;
	}

	pkt->session->lastPacketDirection = dir;

	if( code & SES_ACTION_CLOSE )
	{
		env->sessions->DestroySession( env->sessions, pkt->session );
	}
}


void SessionSetCallback( TcpSession* sess, DataCallbackProc data_callback, ErrorCallbackProc error_callback,
						void* user_data )
{
	_ASSERT( sess );

	sess->data_callback = data_callback;
	sess->error_callback = error_callback;
	sess->user_data = user_data;
	
	if( sess->ssl_session != NULL )
	{
		DSSL_SessionSetCallback( sess->ssl_session, data_callback, error_callback, user_data );
	}
}

/* Plain text TCP reassembler callback */
static int OnNewPlainTextPacket( struct _TcpStream* stream, DSSL_Pkt* pkt )
{
	TcpSession* sess;

	_ASSERT( stream );
	_ASSERT( pkt );

	sess = stream->session;
	_ASSERT( sess );

	if ( sess->data_callback )
	{
		sess->data_callback( SessionGetPacketDirection( sess, pkt ),
			sess->user_data, PKT_TCP_PAYLOAD( pkt ), pkt->data_len );
	}

	return 0;
}

/* TCP reassembler callback function for SSL sessions */
static int OnNewSSLPacket( struct _TcpStream* stream, DSSL_Pkt* pkt )
{
	TcpSession* sess = NULL;
	DSSL_Session* ssl_sess = NULL;
	u_char* data = NULL;
	uint32_t len = 0;
	NM_PacketDir dir = ePacketDirInvalid;
	int rc = DSSL_RC_OK;

	_ASSERT( stream );
	_ASSERT( pkt );

	sess = stream->session;
	_ASSERT( sess );

	ssl_sess = sess->ssl_session;
	if( !ssl_sess )
	{
		_ASSERT( FALSE );
		return NM_ERROR( DSSL_E_UNSPECIFIED_ERROR );
	}

	data = PKT_TCP_PAYLOAD( pkt );
	len = pkt->data_len;
	dir = SessionGetPacketDirection( sess, pkt );

	rc = DSSL_SessionProcessData( ssl_sess, dir, data, len );

	if( ssl_sess->flags & ( SSF_CLOSE_NOTIFY_RECEIVED | SSF_FATAL_ALERT_RECEIVED ) )
	{
		sess->closing = 1;
	}

	return rc;
}


void SessionSetUserData( TcpSession* sess, void* data )
{
	_ASSERT( sess );
	sess->user_data = data;
}


void* SessionGetUserData( TcpSession* sess )
{
	_ASSERT( sess );
	return sess->user_data;
}
