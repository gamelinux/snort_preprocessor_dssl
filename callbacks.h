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
#ifndef _SF_SSL_CALLBACKS_H_
#define _SF_SSL_CALLBACKS_H_

void CapEnv_SessionCallback( CapEnv* env, TcpSession* sess, char event );

void sess_data_callback( NM_PacketDir dir, void* user_data, 
						u_char* pkt_payload, uint32_t pkt_size );

void sess_error_callback( void* user_data, int error_code );

void InitCallbacks( void );
void DeInitCallbacks( void );

#endif
