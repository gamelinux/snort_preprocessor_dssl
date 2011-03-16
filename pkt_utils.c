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

#include "sf_snort_packet.h"
#include "spp_ssl.h"

#include "pkt_utils.h"


/* local definitions */
#define ETHER_HDRLEN		14
#define TCP_HEADER_LEN		20
#define IP_HEADER_LEN		20

#if defined (SOLARIS) || defined (SUNOS) || defined (__sparc__) || defined(__sparc64__) || defined (HPUX)
#define SPARC_TWIDDLE       2
#else
#define SPARC_TWIDDLE       0
#endif

#ifndef IP_MAXPACKET
#define IP_MAXPACKET    65535        /* maximum packet size */
#endif /* IP_MAXPACKET */

#if defined(__linux)
  #include <netinet/ether.h>

#elif defined(__FreeBSD__)
  #include <net/ethernet.h>

#elif defined(WIN32)
  #include "dssl/win32/include/netinet/ether.h"
#endif

/* can't even include tcp.h due to lots of redefinition warning, so work against snort's TCPHeader struct*/
#define SET_TCP_OFFSET(tcph, value)  ((tcph)->offset_reserved = (unsigned char)(((tcph)->offset_reserved & 0x0f) | (value << 4)))

/*
 * Convert SFSnortPacket to libDSSL Packet 
 */
void convert_SFSnortPkt_2_libDSSLPkt( const SFSnortPacket* sf_packet, DSSL_Pkt* dssl_packet )
{
	InitDSSLPkt(  sf_packet->pkt_data, sf_packet->payload_size, sf_packet->pcap_header, dssl_packet );
}


/* Create and init the packet the same fashion as snort's own stream4 does */
SFSnortPacket* CreateSnortPacket( void )
{
	SFSnortPacket* pkt = (SFSnortPacket*) malloc( sizeof( SFSnortPacket ) );
	memset( pkt, 0, sizeof( SFSnortPacket ) );

    pkt->pcap_header = calloc(sizeof(struct pcap_pkthdr)+
                              ETHER_HDRLEN +
                              SPARC_TWIDDLE + IP_MAXPACKET,
                              sizeof(char));


    pkt->pkt_data = ((uint8_t *)pkt->pcap_header) + sizeof(struct pcap_pkthdr);
    pkt->ether_header = ((uint8_t *)pkt->pkt_data + SPARC_TWIDDLE);
    pkt->ip4_header = (IPV4Header*) ((uint8_t *)pkt->ether_header + ETHER_HDRLEN);
    pkt->tcp_header = (TCPHeader*) ((uint8_t *)pkt->ip4_header + sizeof(IPV4Header) );    

    pkt->payload = (uint8_t *)pkt->tcp_header + TCP_HEADER_LEN;

    /* pkt->payload is now pkt +
     *  IPMAX_PACKET - (IP_HEADER_LEN + TCP_HEADER_LEN + ETHER_HDRLEN)
     *  in size
     *
     * This is MAX_STREAM_SIZE
     */

    ((struct ether_header*)pkt->ether_header)->ether_type = htons(0x0800);

	pkt->ip4_header->version_headerlength = 0x0504;
    
	pkt->ip4_header->proto = IPPROTO_TCP;
    pkt->ip4_header->time_to_live = 0xF0;
    pkt->ip4_header->type_service = 0x10;

    SET_TCP_OFFSET(pkt->tcp_header, 0x5);
	pkt->tcp_header->flags = TCPHEADER_PUSH | TCPHEADER_ACK;

	return pkt;
}


void DestroySnortPacket( SFSnortPacket* pkt )
{
	if( pkt->pcap_header ) free( pkt->pcap_header );
	free( pkt );
}


void BuildSnortPacket( const u_char* packet_data, uint16_t packet_len, 
					  SFSnortPacket* sf_packet, SFSnortPacket* proto )
{
	uint32_t ip_len = packet_len + IP_HEADER_LEN  + TCP_HEADER_LEN;

	sf_packet->preprocessor_bit_mask = proto->preprocessor_bit_mask;

    sf_packet->pcap_header->ts.tv_sec = proto->pcap_header->ts.tv_sec;
    sf_packet->pcap_header->ts.tv_usec = proto->pcap_header->ts.tv_usec;

    sf_packet->pcap_header->caplen = ip_len + ETHER_HDRLEN;
    sf_packet->pcap_header->len = sf_packet->pcap_header->caplen;

    sf_packet->ip4_header->data_length = htons((uint16_t) ip_len);
    sf_packet->payload_size = (uint16_t) packet_len;

	if( proto->ether_header != NULL)
	{
		memcpy(sf_packet->ether_header, proto->ether_header, sizeof(ETHER_HDRLEN) );
	}

	memcpy( sf_packet->tcp_header, proto->tcp_header, sizeof( sf_packet->tcp_header ) );
	
	sf_packet->ip4_header->source = proto->ip4_header->source;
	sf_packet->ip4_header->destination = proto->ip4_header->destination;

	sf_packet->src_port = proto->src_port;
	sf_packet->dst_port = proto->dst_port;

    sf_packet->num_tcp_options = 0;
    sf_packet->tcp_last_option_invalid_flag = 0;
    sf_packet->flags = (PKT_REBUILT_STREAM);

    sf_packet->stream_session_ptr = proto->stream_session_ptr;
    sf_packet->stream_ptr = proto->stream_ptr;
}
