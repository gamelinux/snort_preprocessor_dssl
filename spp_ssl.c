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
/*
 * SSL preprocessor
 */
//---------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  /* HAVE_CONFIG_H */
#include <assert.h>

#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_plugin_api.h"
#include "preprocids.h"
#include "debug.h"

#include "spp_ssl.h"
#include "pkt_utils.h"
#include "callbacks.h"

/* TODO: change number and move to file preprocids.h ?*/
#define PP_SSL               77

/*
 * Function prototype(s)
 */
static void SSLInit( u_char* );

static void ProcessSSL( void*, void* );
static void SSLCleanExitFunction( int, void* );
static void SSLRestartFunction( int, void*);
static void SSLConfigCheck( void );

/* Globals */
/* SSL preprocessor global configuration structure */ 

typedef struct _SSLPluginGlobalData
{
	SSLConfig	config;
	CapEnv*		CapEnv;
} SSLPluginGlobalData;


static SSLPluginGlobalData Globals;

/* DPD */
extern DynamicPreprocessorData _dpd;


/* Called at preprocessor setup time. Links preprocessor keyword
 * to corresponding preprocessor initialization function.
 *
 * PARAMETERS:  None.
 * 
 * RETURNS: Nothing.
 *
 */
void SetupSSL()
{
    /* 
	 * Link preprocessor keyword to initialization function in the preprocessor list.
     */
    _dpd.registerPreproc( "SSL", SSLInit );
}


/* Initializes the SSL preprocessor module and registers
 * it in the preprocessor list.
 * 
 * PARAMETERS:  
 *
 * argp:        Pointer to argument string to process for config
 *                      data.
 *
 * RETURNS:     Nothing. 
 */

int LoadConfig( const u_char* conf, SSLConfig* cfg );

static void SSLInit( u_char* argp )
{
    int rc;
	int i = 0;

	memset( &Globals, 0, sizeof(Globals) );

	SSL_library_init();	
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	LoadConfig( argp, &Globals.config );
    //ParseSSLArgs( argp, &Globals.config );

	/* Create global DSSL structures */	
	Globals.CapEnv = (CapEnv*) CapEnvCreate( NULL, MAX_CAPENV_BUF, 0 );
	assert(Globals.CapEnv);

	rc = 0;


	//We may have multiple SSL_servers
	for ( i = 0; i < Globals.config.server_cnt; i++ )
	{
		rc = CapEnvSetSSL_ServerInfo( Globals.CapEnv, 
			                          &Globals.config.server[i]->server_ip, 
			                          Globals.config.server[i]->port,
			                          Globals.config.server[i]->server_certfile, 
									  Globals.config.server[i]->server_keyfile,
		  				              Globals.config.server[i]->password 
									 );
		if (rc != DSSL_RC_OK)
		{			
			char err_str[255];
			memset( err_str, 0, sizeof(err_str) );
			sprintf( err_str,"Preprocessor: error loading SSL server configuration at pos[%i]; error code=%d\n", i+1, rc );
			_dpd.fatalMsg( err_str ); 
		}
	}

	if( rc == DSSL_RC_OK )
	{
		InitCallbacks();

		/* Set callback for creating/closing sessions*/
		CapEnvSetSessionCallback( Globals.CapEnv, CapEnv_SessionCallback, NULL );

		_dpd.addPreproc( ProcessSSL, PRIORITY_TRANSPORT, PP_SSL );
		_dpd.addPreprocExit( SSLCleanExitFunction, NULL, PRIORITY_LAST, PP_SSL );
		_dpd.addPreprocRestart( SSLRestartFunction, NULL, PRIORITY_LAST, PP_SSL );
		_dpd.addPreprocConfCheck( SSLConfigCheck );
	        
		DEBUG_WRAP(_dpd.debugMsg(DEBUG_PLUGIN, "Preprocessor: SSL is initialized\n"););
	}
}


/* Verify configuration
 *
 * PARAMETERS:  None
 *
 * RETURNS:     Nothing.
 */
static void SSLConfigCheck( void )
{
}


/* Main runtime entry point for SSL preprocessor. 
 * 
 * PARAMETERS:
 * p:           Pointer to current packet to process. 
 *
 * RETURNS:     Nothing.
 */

SFSnortPacket*	current_snort_packet = NULL;

static void ProcessSSL( void* pkt, void* context )
{    
	SFSnortPacket *p = (SFSnortPacket *)pkt;
	
	DSSL_Pkt p1; //libDSSL Packet

    if (!p) return;

	/* SSL only goes over TCP*/
    if( !IsTCP(p) ) return;

    /* Ignore packets with "PKT_REBUILT_STREAM" flag */
	if (p->flags & PKT_REBUILT_STREAM ) return;

	/* process SSL packets only*/
	if( CapEnvFindDSSL_ServerInfo( Globals.CapEnv, &p->ip4_header->source, ntohs(p->tcp_header->source_port) ) ||
		CapEnvFindDSSL_ServerInfo( Globals.CapEnv, &p->ip4_header->destination, ntohs(p->tcp_header->destination_port) ) )
	{
		current_snort_packet = p;
		memset( &p1, 0, sizeof(DSSL_Pkt) ); 
		convert_SFSnortPkt_2_libDSSLPkt( p, &p1 );
		CapEnvProcessPacket( Globals.CapEnv, &p1 );
	}
	else
	{
		printf( "not ssl packet\n" );
	}
}


/* 
 * Function: SSLCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting, if there's
 *          any cleanup that needs to be performed (e.g. closing files)
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    function when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void SSLCleanExitFunction(int signal, void *data)
{
	DeInitCallbacks();
}


/* 
 * Function: SSLRestartFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is restarting on a SIGHUP,
 *          if there's any initialization or cleanup that needs to happen
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void SSLRestartFunction(int signal, void *foo)
{
}
