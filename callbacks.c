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
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_plugin_api.h"

#include "spp_ssl.h"
#include "callbacks.h"
#include "pkt_utils.h"

/* DPD */
extern DynamicPreprocessorData _dpd;


static SFSnortPacket* decoded_packet = NULL;

void InitCallbacks( void )
{
	decoded_packet = CreateSnortPacket();
}


void DeInitCallbacks( void )
{
	if( decoded_packet ) 
	{
		DestroySnortPacket( decoded_packet );
		decoded_packet = NULL;
	}
}


static void OnNewSession( CapEnv* env, TcpSession* sess )
{
	SessionSetCallback( sess, sess_data_callback, sess_error_callback, NULL );
}


void CapEnv_SessionCallback( CapEnv* env, TcpSession* sess, char event )
{
	switch( event )
	{
		case DSSL_EVENT_NEW_SESSION:
			OnNewSession( env, sess );
			break;
		case DSSL_EVENT_SESSION_CLOSING:
			break;		
	}
}

void sess_data_callback( NM_PacketDir dir, void* user_data, u_char* pkt_payload,
                                uint32_t pkt_size )
{  
  /* put the newly arrived data to the packet */
  BuildSnortPacket( pkt_payload, (uint16_t) pkt_size, decoded_packet, current_snort_packet );

  /* ... and send that packet back to the snort detection routine */
  (*_dpd.detect)( decoded_packet );
}


void sess_error_callback( void* user_data, int error_code )
{
}
