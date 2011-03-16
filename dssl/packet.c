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
#include "packet.h"

uint32_t PktNextTcpSeqExpected( DSSL_Pkt* pkt )
{
	uint32_t th_seq;
	th_seq = ntohl( pkt->tcp_header->th_seq );

	if( pkt->tcp_header->th_flags & TH_SYN )
		return th_seq + 1;
	else
		return th_seq + pkt->data_len;
}


DSSL_Pkt* PktClone( DSSL_Pkt* src )
{
	DSSL_Pkt* pClone;

	pClone = malloc( sizeof( DSSL_Pkt ) + src->pcap_header.caplen );
	memcpy( &pClone->pcap_header, &src->pcap_header, sizeof( struct pcap_pkthdr ) );
	memcpy( (u_char*)pClone + sizeof(*pClone), src->pcap_ptr, src->pcap_header.caplen );

	pClone->data_len = src->data_len;
	pClone->pcap_ptr = (u_char*) pClone + sizeof(*pClone);
	pClone->session = src->session;

	pClone->ether_header = (struct ether_header*)
			( pClone->pcap_ptr + ((u_char*)src->ether_header - src->pcap_ptr ) );
	pClone->ip_header = (struct ip*) 
			( pClone->pcap_ptr + ((u_char*) src->ip_header - src->pcap_ptr ) );
	pClone->tcp_header = (struct tcphdr*)
			( pClone->pcap_ptr + ((u_char*) src->tcp_header - src->pcap_ptr ) );

	pClone->prev = pClone->next = NULL;

	return pClone;
}

void PktFree( DSSL_Pkt* pkt )
{
	free( pkt );
}

