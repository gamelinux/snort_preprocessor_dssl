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
#ifndef __DSSL_LOG_H__
#define __DSSL_LOG_H__

#ifdef NM_TRACE_SSL
	#define NM_TRACE_SSL_HANDSHAKE
	#define NM_TRACE_SSL_RECORD
	#define NM_TRACE_SSL_SESSIONS
#endif


#ifdef NM_TRACE_TCP
	#define NM_TRACE_TCP_STREAMS
#endif

void nmLogMessage( uint32_t category, const char* fmt, ... );

#define LG_SEVERITY_MESSAGE	0x1000
#define LG_SEVERITY_WARNING	0x2000
#define LG_SEVERITY_ERROR	0x3000

#define LG_SEVERITY_MASK	0xf000

#define LG_CATEGORY_GENERAL	0x0000
#define LG_CATEGORY_CAPTURE	0x0001

#define ERR_GENERAL	(LG_SEVERITY_ERROR | LG_CATEGORY_GENERAL)
#define ERR_CAPTURE	(LG_SEVERITY_ERROR | LG_CATEGORY_CAPTURE)

#ifdef _DEBUG
	#define NM_ENABLE_TRACE
#endif

#ifdef NM_ENABLE_TRACE
	#define DEBUG_TRACE0( fmt ) printf( fmt )
	#define DEBUG_TRACE1( fmt, p1 ) printf( fmt, p1 )
	#define DEBUG_TRACE2( fmt, p1, p2 ) printf( fmt, p1, p2 )
	#define DEBUG_TRACE3( fmt, p1, p2, p3 ) printf( fmt, p1, p2, p3 )
#else
	#define DEBUG_TRACE0( fmt )
	#define DEBUG_TRACE1( fmt, p1 ) 
	#define DEBUG_TRACE2( fmt, p1, p2 ) 
	#define DEBUG_TRACE3( fmt, p1, p2, p3 )
#endif

#endif
