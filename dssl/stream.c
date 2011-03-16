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
#include "stream.h"
#include "session.h"

/* StreamAddPacket return codes */
#define PKT_BOGUS			0x80000000
#define PKT_RETRANS			0x40000000
#define PKT_INSERTED		0x20000000
#define PKT_DROPPED			0x10000000
#define PKT_NEW_REASSEMBLED	0x01000000
#define PKT_AFTER			0x00000001
#define PKT_BEFORE			0x00000002
#define PKT_INSERTED_AFTER	( PKT_INSERTED | PKT_AFTER )
#define PKT_INSERTED_BEFORE ( PKT_INSERTED | PKT_BEFORE )


#ifdef _DEBUG
const char* GetStreamStateName( TcpStreamState state )
{
	switch( state )
	{
		case tcpClosed:			return "CLOSED";
		case tcpListen:			return "LISTEN";
		case tcpSynSent:		return "SYN-SENT";
		case tcpSynReceived:	return "SYN-RECEIVED";
		case tcpEstablished:	return "ESTABLISHED";
		case tcpFinWait1:		return "FIN-WAIT-1";
		case tcpFinWait2:		return "FIN-WAIT-2";
		case tcpCloseWait:		return "CLOSE-WAIT";
		case tcpClosing:		return "CLOSING";
		case tcpLastACK:		return "LAST-ACK";
		case tcpTimeWait:		return "TIME_WAIT";
	}

	return "UNKNOWN";
}
#endif

/* Local prototypes */
static void ClearStateChangeData( TcpStream* stream );


void StreamInit( TcpStream* stream, TcpSession* sess, uint32_t ip, uint16_t port, TcpStreamState initState )
{
	_ASSERT( stream );

	stream->ip_addr = ip;
	stream->port = port;
    stream->pktHead = NULL;
    stream->pktTail = NULL;
    stream->pktLastReassembled = NULL;
	stream->state = initState;
	stream->nextSeqExpected = 0;
	stream->session = sess;

	ClearStateChangeData( stream );
}

static int StreamGetPacketCount( TcpStream* stream )
{
	int cnt = 0;
	DSSL_Pkt* pkt = stream->pktHead;

	while( pkt )
	{
		cnt++;
		pkt = pkt->next;
	}

	return cnt;
}


void StreamFreeData( TcpStream* stream )
{
	DSSL_Pkt* pkt = stream->pktHead;

#ifdef NM_TRACE_TCP_STREAMS
	DEBUG_TRACE2( "\nFreeStreamData: stream %p; %d packets freed",
		stream, StreamGetPacketCount( stream ) );
#endif

	while( pkt ) 
	{
		DSSL_Pkt* t = pkt->next;
		PktFree( pkt );
		pkt = t;
	}

	stream->pktTail = stream->pktHead = NULL;
	stream->pktLastReassembled = NULL;
	stream->nextSeqExpected = 0;

}


void StreamFlush( TcpStream* stream )
{
	uint32_t nextSeq;

	_ASSERT( stream );

	nextSeq = stream->pktTail ? PktNextTcpSeqExpected( stream->pktTail ) : 0;


	StreamFreeData( stream );
	stream->nextSeqExpected = nextSeq;
}


static int HasSeqGapInFront( DSSL_Pkt* p )
{
	if( p->prev == NULL ) return 0;

	return PktNextTcpSeqExpected( p->prev ) != PKT_TCP_SEQ( p );
}

static int HasSeqOverrunGapInFront( DSSL_Pkt* p )
{
	if( p->prev == NULL ) return 0;

	return PKT_TCP_SEQ( p->prev ) > PKT_TCP_SEQ( p );
}


/* Checks if this packet's position is before p */
static int PacketInFrontGap( DSSL_Pkt* p, DSSL_Pkt* toInsert )
{
	uint32_t current_seq = PKT_TCP_SEQ( p );
	uint32_t seq = PKT_TCP_SEQ( toInsert );
	int rc = 0;

	if( !HasSeqGapInFront( p ) ) return rc;

	_ASSERT( p->prev );

	if( HasSeqOverrunGapInFront( p ) )
	{
		/* previous packet has sequence overrun, hence compare just 
		the sequence numbers */
		_ASSERT( seq <= current_seq );
		rc = 1;
	}
	else
	{
		rc = (PktNextTcpSeqExpected( p->prev ) <= seq && 
			current_seq >= PktNextTcpSeqExpected( toInsert ));
	}

	return rc;
}


static void StreamInsertAfter( TcpStream* stream, DSSL_Pkt* pktInsert, DSSL_Pkt* pktAfter )
{
	pktInsert->prev = pktAfter;
	pktInsert->next = pktAfter->next;
	pktAfter->next = pktInsert;
	if( pktInsert->next ) pktInsert->next->prev = pktInsert;

	if( pktAfter == stream->pktTail ) stream->pktTail = pktInsert;
}


static void StreamInsertBefore( TcpStream* stream, DSSL_Pkt* pktInsert, DSSL_Pkt* pktBefore )
{
	_ASSERT( pktBefore );

	pktInsert->prev = pktBefore->prev;

	if( pktBefore->prev )
	{
		_ASSERT( pktBefore->prev->next == pktBefore );
		pktBefore->prev->next = pktInsert;
	}
	else
	{
		_ASSERT( pktBefore == stream->pktHead );
		stream->pktHead = pktInsert;
	}

	pktBefore->prev = pktInsert;
	pktInsert->next = pktBefore;
}


static int StreamAddPacket( TcpStream* stream, DSSL_Pkt* pkt )
{
	uint32_t seq = PKT_TCP_SEQ( pkt );
	uint32_t next_seq = PktNextTcpSeqExpected( pkt );
	DSSL_Pkt* p = stream->pktTail;
	int processed = 0;

	if( p == NULL )
	{
		stream->pktHead = stream->pktTail = PktClone( pkt );
		_ASSERT( stream->pktHead->prev == NULL );
		_ASSERT( stream->pktHead->next == NULL );
		processed |= PKT_INSERTED;
		
		if( stream->nextSeqExpected == seq )
		{
			processed |= PKT_NEW_REASSEMBLED;
		}

		return processed;
	}

	while( p && !processed )
	{
		if( PktNextTcpSeqExpected( p ) == seq )
		{
			/* Exact match - pkt is next to p */
	
			if( p == stream->pktLastReassembled )
			{
				processed |= PKT_NEW_REASSEMBLED;
			}
			StreamInsertAfter( stream, PktClone( pkt ), p );
			processed |= PKT_INSERTED_AFTER;

		} 
		else if( PktNextTcpSeqExpected( p ) < seq )
		{
			/* pkt has sequence number greater than the "next packet after p",
			but the latter didn't show up yet */

			StreamInsertAfter( stream, PktClone( pkt ), p );
			processed |= PKT_INSERTED_AFTER;
		}
		else if( PKT_TCP_SEQ( p ) == next_seq )
		{
			/* Exact match - pkt is previous to p */ 

			if( (stream->pktLastReassembled && p->prev == stream->pktLastReassembled) ||
				(p == stream->pktHead && stream->nextSeqExpected == seq) )
			{
				processed |= PKT_NEW_REASSEMBLED;
			}
			StreamInsertBefore( stream, PktClone( pkt ), p );
			processed |= PKT_INSERTED_BEFORE;
		}
		else if( PKT_TCP_SEQ( p ) == PKT_TCP_SEQ( pkt ) )
		{
			/* Retransmission */
			processed |= (PKT_DROPPED | PKT_RETRANS);
		}
		else if( PacketInFrontGap( p, pkt ) || (p->prev == NULL) )
		{
			if( p->prev )
			{
				if( p->prev == stream->pktLastReassembled &&
					PktNextTcpSeqExpected( p->prev ) == seq )
				{
					processed |= PKT_NEW_REASSEMBLED;
				}
			}
			else if( stream->nextSeqExpected == seq )
			{
				processed |= PKT_NEW_REASSEMBLED;
			}

			/* Fill in the gap */
			StreamInsertBefore( stream, PktClone( pkt ), p );
			processed |= PKT_INSERTED_BEFORE;
		}

		if( !processed && p == stream->pktLastReassembled ) 
		{
			/*	Everything beyond that has been fully reassembled,
				no point to search for a fit anymore 
			*/
			processed = (PKT_DROPPED | PKT_BOGUS);
		}

		if( !processed )
		{
			p = p->prev;
		}
	}

	return processed;
}

static int IsNextPacket( TcpStream* stream, DSSL_Pkt* pkt )
{
	_ASSERT( stream );
	_ASSERT( pkt );

	return ( stream->nextSeqExpected == PKT_TCP_SEQ( pkt ) 
			&& stream->pktHead == NULL );
}

/*
========================================================
	StreamProcessPacket: Main packet processing routine 
========================================================
*/
int StreamProcessPacket( TcpStream* stream, DSSL_Pkt* pkt )
{
	int rc = DSSL_RC_OK;
	int reasm_code = 0;

	if( pkt->tcp_header->th_flags & TH_SYN )
	{
		_ASSERT( pkt->data_len == 0 );
		stream->nextSeqExpected = PktNextTcpSeqExpected( pkt );
		return rc;
	}

	if( pkt->data_len == 0 ) return rc;

	if( IsNextPacket( stream, pkt ) )
	{
		rc = stream->session->OnNewPacket( stream, pkt );
		stream->nextSeqExpected = PktNextTcpSeqExpected( pkt );
		return rc;
	}

	reasm_code = StreamAddPacket( stream, pkt );

	if( reasm_code & PKT_NEW_REASSEMBLED )
	{
		/* process new data here*/
		DSSL_Pkt* cur;

		_ASSERT( stream->session->OnNewPacket != NULL );
		
		if( stream->pktLastReassembled )
		{
			cur = stream->pktLastReassembled->next;
		}
		else
		{
			cur = stream->pktHead;
		}

		while( cur && !HasSeqGapInFront( cur ) )
		{
			rc = stream->session->OnNewPacket( stream, cur );
			if( NM_IS_FAILED(rc) ) break;

			cur = cur->next;
		}

		if( cur )
		{
			/* update the last reassembled packet bookmark */
			stream->pktLastReassembled = cur->prev;
		}
		else
		{
			StreamFlush( stream );
		}
	}
	else
	{
		rc = (reasm_code & PKT_BOGUS) ? NM_ERROR( DSSL_E_TCP_CANT_REASSEMBLE ) : DSSL_RC_OK;
	}

	return rc;
}


static void ClearStateChangeData( TcpStream* stream )
{
	stream->stch_action = stchNoAction;
	stream->stch_flags = 0;
	stream->stch_ack = 0;
	stream->stch_state = tcpClosed;
}


void StreamStateChangeOnACK( TcpStream* stream, TcpStreamState state, uint32_t ack )
{
	stream->stch_action = stchCheckACK;
	stream->stch_ack = ack;
	stream->stch_state = state;
}


void StreamStateChangeOnFlags( TcpStream* stream, TcpStreamState state, uint8_t flags )
{
	stream->stch_action = stchCheckFlags;
	stream->stch_flags = flags;
	stream->stch_state = state;
}


static void STREAM_CHANGE_STATE( TcpStream* stream, TcpStreamState state )
{
	SET_STREAM_STATE( stream, state );
	ClearStateChangeData( stream );
}


void StreamCheckStateChange( TcpStream* stream, DSSL_Pkt* pkt )
{
	switch( stream->stch_action )
	{
	case stchCheckACK:
		if( ntohl( pkt->tcp_header->th_ack) >= stream->stch_ack )
		{
			STREAM_CHANGE_STATE( stream, stream->stch_state );
		}
		break;

	case stchCheckFlags:
		if( pkt->tcp_header->th_flags & stream->stch_flags )
		{
			STREAM_CHANGE_STATE( stream, stream->stch_state );
		}
		break;


	default:
		_ASSERT( FALSE );
	case stchNoAction:
		break;
	}
}
