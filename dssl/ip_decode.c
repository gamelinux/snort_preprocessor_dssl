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

void DecodeIpPacket( CapEnv* env, DSSL_Pkt* pkt, const uint8_t* data, const int len )
{
	int ip_len, ip_hdrlen;

	pkt->ip_header = (struct ip*) data;

	if( len < sizeof(struct ip) )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Invalid IP header length!" );
		return;
	}

	if( IP_V(pkt->ip_header) != 4 )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Unsupported IP version: %d",
				(int)IP_V(pkt->ip_header) );
		return;
	}

	/*TODO: reassemble fragmented packets*/

	ip_len = ntohs(pkt->ip_header->ip_len);
	ip_hdrlen = IP_HL(pkt->ip_header) << 2;

	if( ip_hdrlen < sizeof(struct ip) )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Bogus IP header!" );
		return;
	}

	/* SSL can run only on TCP */
	if( pkt->ip_header->ip_p == IPPROTO_TCP )
	{
		DecodeTcpPacket( env, pkt, data + ip_hdrlen, ip_len - ip_hdrlen );
	}
}
