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
#include "decode.h"

void pcap_cb_ethernet( u_char *ptr, const struct pcap_pkthdr *header, const u_char *pkt_data );

#ifndef DSSL_NO_PCAP
pcap_handler GetPcapHandler( pcap_t* p )
{
	pcap_handler rc = NULL;

	if( !p ) { _ASSERT( FALSE ); return NULL; }

	switch( pcap_datalink( p ) )
	{
		case DLT_EN10MB: rc = pcap_cb_ethernet; break;
		default:
			/*Unsupported link type*/
			rc = NULL;
			break;
	}

	return rc;
}
#endif


void pcap_cb_ethernet( u_char *ptr, const struct pcap_pkthdr *header, const u_char *pkt_data )
{
	CapEnv* env = (CapEnv*)ptr;
	DSSL_Pkt packet;
	int len = header->caplen;

	memset( &packet, 0, sizeof( packet ) );
	/* TODO: remove header info if not needed */
	memcpy( &packet.pcap_header, header, sizeof(packet.pcap_header) );

	packet.pcap_ptr = pkt_data;

	packet.ether_header = (struct ether_header*) pkt_data;

	if( len < ETHER_HDRLEN )
	{
		nmLogMessage( ERR_CAPTURE, "pcap_cb_ethernet: Invalid ethernet header length!" );
		return;
	}

	if( ntohs(packet.ether_header->ether_type) == ETHERTYPE_IP )
	{
		DecodeIpPacket( env, &packet, pkt_data + ETHER_HDRLEN, len - ETHER_HDRLEN );
	}
}
