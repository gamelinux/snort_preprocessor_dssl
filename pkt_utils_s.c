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
#include "spp_ssl.h"
#include "pkt_utils.h"

/* local definitions */
#define ETHER_HDRLEN		14
#define TCP_HEADER_LEN		20

#if defined (SOLARIS) || defined (SUNOS) || defined (__sparc__) || defined(__sparc64__) || defined (HPUX)
#define SPARC_TWIDDLE       2
#else
#define SPARC_TWIDDLE       0
#endif

#if defined(__linux)
  #include <netinet/ip.h>
  #include <netinet/ether.h>
  #define IP_HL(ip) ((ip)->ip_hl)
  #define SET_IP_VER(iph, value ) ((iph)->ip_v = value)
  #define SET_IP_HLEN(iph, value)  ((iph)->ip_hl = (value & 0x0f)))

#elif defined(__FreeBSD__)
  #include <net/ethernet.h>
  #define IP_HL(ip) ((ip)->ip_hl)
  #define SET_IP_VER(iph, value ) ((iph)->ip_v = value)
  #define SET_IP_HLEN(iph, value)  ((iph)->ip_hl = (value & 0x0f))
#elif defined(WIN32)
  #include "./dssl/win32/include/netinet/ip.h"
  #include "./dssl/win32/include/netinet/ether.h"
  #define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
  #define SET_IP_VER(iph, value)  ((iph)->ip_vhl = (unsigned char)(((iph)->ip_vhl & 0x0f) | (value << 4)))
  #define SET_IP_HLEN(iph, value)  ((iph)->ip_vhl = (unsigned char)(((iph)->ip_vhl & 0xf0) | (value & 0x0f)))
#endif

/* can't even include tcp.h due to lots of redefinition warning, so work against snort's TCPHeader struct*/
#define SET_TCP_OFFSET(tcph, value)  ((tcph)->offset_reserved = (unsigned char)(((tcph)->offset_reserved & 0x0f) | (value << 4)))

/*
 * Convert SFSnortPacket to libDSSL Packet 
 */
void InitDSSLPkt( const u_char* pkt_data, uint16_t tcp_payload_len, const struct pcap_pkthdr* pcap_hdr,
				 DSSL_Pkt* dssl_packet )
{	
	uint32_t iph_len = 0;

	memcpy( &dssl_packet->pcap_header, pcap_hdr, sizeof(struct pcap_pkthdr) );
	
	dssl_packet->pcap_ptr = pkt_data;

	dssl_packet->ether_header = (struct ether_header*) (dssl_packet->pcap_ptr);
	dssl_packet->ip_header = (struct ip*) (dssl_packet->pcap_ptr + ETHER_HDRLEN);
	
	iph_len = IP_HL(dssl_packet->ip_header) << 2;
	dssl_packet->tcp_header = (struct tcphdr*) (dssl_packet->pcap_ptr + ETHER_HDRLEN + iph_len);
	
	dssl_packet->session = NULL;
	dssl_packet->next = NULL;
	dssl_packet->prev = NULL;

	dssl_packet->data_len = tcp_payload_len;
}
