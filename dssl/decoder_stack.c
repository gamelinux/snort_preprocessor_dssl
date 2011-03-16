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
#include "decoder_stack.h"
#include "ssl_session.h"
#include "ssl_decode.h"
#include "ssl_decode_hs.h"

void dssl_decoder_stack_init( dssl_decoder_stack* stack )
{
	memset( stack, 0, sizeof(stack) );
	stack->state = SS_Initial;
}


void dssl_decoder_stack_deinit( dssl_decoder_stack* stack )
{
	dssl_decoder_deinit( &stack->dalert );
	dssl_decoder_deinit( &stack->dappdata );
	dssl_decoder_deinit( &stack->dcss );
	dssl_decoder_deinit( &stack->dhandshake );
	dssl_decoder_deinit( &stack->drecord );

	if( stack->cipher )
	{
		EVP_CIPHER_CTX_cleanup( stack->cipher );
		free( stack->cipher );
		stack->cipher = NULL;
	}

	if( stack->cipher_new )
	{
		EVP_CIPHER_CTX_cleanup( stack->cipher_new );
		free( stack->cipher_new );
		stack->cipher_new = NULL;
	}

	stack->md = stack->md_new = NULL;
}


int sslc_is_decoder_stack_set( dssl_decoder_stack* s)
{
	return s->sess != NULL;
}


int dssl_decoder_stack_set( dssl_decoder_stack* d, DSSL_Session* sess, uint16_t version )
{
	int rc = DSSL_RC_OK;

	d->sess = NULL;

	switch( version )
	{
	case SSL3_VERSION:
	case TLS1_VERSION:
		dssl_decoder_init( &d->drecord, ssl3_record_layer_decoder, d );
		dssl_decoder_init( &d->dhandshake, ssl3_decode_handshake_record, d );
		dssl_decoder_init( &d->dcss, ssl3_change_cipher_spec_decoder, d );
		dssl_decoder_init( &d->dappdata, ssl_application_data_decoder, d );
		dssl_decoder_init( &d->dalert, ssl3_alert_decoder, d );
		break;

	case SSL2_VERSION:
		rc = NM_ERROR( DSSL_E_NOT_IMPL );
		break;

	default:
		rc = NM_ERROR( DSSL_E_SSL_UNKNOWN_VERSION );
		break;
	}

	if( rc == DSSL_RC_OK ) d->sess = sess;

	return rc;
}

int dssl_decoder_stack_process( dssl_decoder_stack* stack, NM_PacketDir dir, u_char* data, uint32_t len )
{
	return dssl_decoder_process( &stack->drecord, dir, data, len );
}
