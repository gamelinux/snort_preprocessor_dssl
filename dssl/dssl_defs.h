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
#ifndef __DSSL_DSSL_DEFS_H__
#define __DSSL_DSSL_DEFS_H__

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum NM_SessionType_
{
	eSessionTypeNull = 0,
	eSessionTypeTcp = 1,
	eSessionTypeSSL = 2
} NM_SessionType;

typedef enum NM_PacketDir_
{
	ePacketDirInvalid,
	ePacketDirFromClient,
	ePacketDirFromServer
} NM_PacketDir;

/* TCP or SSL decoder callback */
typedef void (*DataCallbackProc)( NM_PacketDir dir, void* user_data, u_char* data, uint32_t len );
typedef void (*ErrorCallbackProc)( void* user_data, int error_code );

#define IS_ENOUGH_LENGTH( org_data, org_len, cur_data, size_needed ) ( (org_data) + (org_len) >= (cur_data) + (size_needed) )
#define _ASSERT_STATIC(e) 1/(e)
#define UNUSED_PARAM( p ) (p)


/*TODO: remove to a separate file */
#define SSL3_HEADER_LEN		5
#define SSL20_CLIENT_HELLO_MIN_LEN		9
#define SSL20_CLIENT_HELLO_HDR_LEN		2
#define SSL20_SERVER_HELLO_MIN_LEN		7
#define SSL3_SERVER_HELLO_MIN_LEN		38
#define SSL3_HANDSHAKE_HEADER_LEN		4

#define DSSL_SESSION_ID_SIZE	32

/* Forward declarations */

struct DSSL_Pkt_;
typedef struct DSSL_Pkt_ DSSL_Pkt;

struct DSSL_Session_;
typedef struct DSSL_Session_ DSSL_Session;

struct DSSL_ServerInfo_;
typedef struct DSSL_ServerInfo_ DSSL_ServerInfo;

struct dssl_SessionKeyTable_;
typedef struct dssl_SessionKeyTable_ dssl_SessionKeyTable;

typedef struct dssl_SessionTable_ dssl_SessionTable;

struct _TcpSession;
typedef struct _TcpSession TcpSession;

struct CapEnv_;
typedef struct CapEnv_ CapEnv;

struct _TcpStream;
typedef struct _TcpStream TcpStream;

struct _DSSL_CipherSuite;
typedef struct _DSSL_CipherSuite DSSL_CipherSuite;

struct dssl_decoder_;
typedef struct dssl_decoder_ dssl_decoder;

struct dssl_decoder_stack_;
typedef struct dssl_decoder_stack_ dssl_decoder_stack;

/*
#define NM_MULTI_THREADED_SSL
*/

#ifdef  __cplusplus
}
#endif

#endif
