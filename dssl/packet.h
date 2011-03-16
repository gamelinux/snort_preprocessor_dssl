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
#ifndef __DSSL_PACKET_H__
#define __DSSL_PACKET_H__

#include "dssl_defs.h"
#ifdef  __cplusplus
extern "C" {
#endif


struct DSSL_Pkt_
{
	/* Original pcap captured data*/
	const u_char*				pcap_ptr;
	struct pcap_pkthdr			pcap_header;

	/*Protocol headers*/
	struct ether_header*		ether_header;
	struct ip*					ip_header;
	struct tcphdr*				tcp_header;

	/*TCP session*/
	TcpSession*					session;

	struct DSSL_Pkt_*				next;
	struct DSSL_Pkt_*				prev;

	uint16_t					data_len;
};

#define PKT_TCP_SEQ( p ) ntohl( (p)->tcp_header->th_seq )
#define PKT_TCP_DPORT( p ) ntohs( (p)->tcp_header->th_dport )
#define PKT_TCP_SPORT( p ) ntohs( (p)->tcp_header->th_sport )

#define PKT_TCP_PAYLOAD( p ) ((u_char*)((p)->tcp_header) + NM_TCP_HDR_LEN( (p)->tcp_header ))

uint32_t PktNextTcpSeqExpected( DSSL_Pkt* pkt );

DSSL_Pkt* PktClone( DSSL_Pkt* src );
void PktFree( DSSL_Pkt* pkt );

#ifdef  __cplusplus
}
#endif

#endif
