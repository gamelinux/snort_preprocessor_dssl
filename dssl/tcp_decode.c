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
#include "session.h"

void DecodeTcpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len )
{
	int tcp_hdr_len;

	/* Check the packet length */
	if( len < sizeof(struct tcphdr) )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than minimal TCP header size", len );
		return;
	}

	pkt->tcp_header = (struct tcphdr*) data;

	tcp_hdr_len = NM_TCP_HDR_LEN( pkt->tcp_header );

	if( len < tcp_hdr_len )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than TCP header size specified (%d)", 
			len, tcp_hdr_len );
		return;
	}

	pkt->data_len = (uint16_t)( len - tcp_hdr_len );

	CapEnvProcessPacket( env, pkt );
}
