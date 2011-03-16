/*
** Copyright (C) 2005-2007 SSLTech.net.
**
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
*/
#ifndef _SF_SSL_PKT_UTILS_H_
#define _SF_SSL_PKT_UTILS_H_

/* pkt_utils: packet building and conversion routines */

struct _SFSnortPacket;
struct DSSL_Pkt_;

void convert_SFSnortPkt_2_libDSSLPkt( const struct _SFSnortPacket* sf_packet, struct DSSL_Pkt_* dssl_packet );

void InitDSSLPkt( const u_char* pkt_data, uint16_t tcp_payload_len, const struct pcap_pkthdr* pcap_hdr,
				 DSSL_Pkt* dssl_packet );

/* create and init the "fake" packet that is used to carry the decoded SSL data back to Snort */
struct _SFSnortPacket* CreateSnortPacket( void );
/* destroy the packet created by CreateSnortPacket*/
void DestroySnortPacket( struct _SFSnortPacket* pkt );

/* build a previously initialized "fake" packet with actual data (decrypted SSL that is) */
void BuildSnortPacket( const u_char* packet_data, uint16_t packet_len, 
					  struct _SFSnortPacket* sf_packet, struct _SFSnortPacket* proto );

#endif
