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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  /* HAVE_CONFIG_H */
#ifdef __linux
	#include <arpa/inet.h>
#endif

#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "debug.h"

#include "spp_ssl.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* DPD */
extern DynamicPreprocessorData _dpd;

/* prototypes */
static void PrintSSLConfig( const SSLConfig* ssl_config );

typedef enum _ConfigTokens
{
	Token_LeftBrace = 0,
	Token_RightBrace,
	Token_Server,
	Token_IP,
	Token_Port,
	Token_KeyFile,
	Token_Pwd,
	Token_PwdFile,
	Token_EOF,
	Token_Unknown
} ConfigToken;

#define ARRAY_SIZE( a ) ( sizeof(a)/sizeof(a[0]) )
#define MAIN_SEPARATOR					" \t\n\r"
#define MAX_TOKEN_LEN		512
#define LAST_LITERAL_TOKEN	Token_PwdFile
#define TOKEN_COUNT (Token_Unknown - Token_LeftBrace)
#define CONFIG_PARSE_ERROR	(-1)


static int IsSeparator( u_char ch )
{
	return ch == ' ' || ch == '\r' || ch == '\t' || ch == '\n';
}

typedef struct ParseContext_
{
	u_char*		input;
	u_char*		token;
	SSLConfig*	config;
} ParseContext;


static const u_char* g_Tokens[] = 
{
	"{", "}", "server", "ip", "port", "keyfile", "pwd", "pwdfile"
};

static const u_char* ERROR_PREFIX = "SSL preprocessor error";
static u_char error_buffer[4096];


/* Converts token enum into a string representation*/
static const u_char* TokenToString( ConfigToken token )
{
	if( token < Token_LeftBrace ) return "#INVALID_TOKEN";
	if( token <= LAST_LITERAL_TOKEN ) return g_Tokens[ token - Token_LeftBrace ];
	if( token == Token_EOF ) return "<EOF>";
	return "Unknown";
}


/* Formats a list of tokens to a string */
static const u_char* TokensToString( ConfigToken* tokens, int sz )
{
	static u_char buff[1024];
	int i = 0;

	buff[0] = 0;

	for( i = 0; i < sz; i++ )
	{
		if( i != 0 ) strcat( buff, ", " );
		strcat( buff, "'" );
		strcat( buff, TokenToString( tokens[i] ) );
		strcat( buff, "'" );
	}

	return buff;
}

/* read the next token from the ParseContext input */
static void Advance( ParseContext* ctx )
{
	ctx->token = strtok( ctx->input, MAIN_SEPARATOR );
	if( ctx->input ) ctx->input = NULL;
}

/* Advance to the next token and find its corresponding enum */
static ConfigToken ParseToken( ParseContext* ctx )
{
	int i=0;

	Advance( ctx );
	if( !ctx->token ) return Token_EOF;

	for( i = 0; i < ARRAY_SIZE(g_Tokens); i++ )
	{
		if( stricmp( g_Tokens[i], ctx->token ) == 0 ) return (ConfigToken)i;
	}

	return Token_Unknown;
}

/* Scans the next token and checks that it is the one that's expected */
static int MatchToken( ParseContext* ctx, ConfigToken token )
{
	ConfigToken parsed_token;
	
	parsed_token = ParseToken( ctx );

	if( parsed_token != token )
	{
		if( parsed_token != Token_Unknown ) 
		{
			sprintf( error_buffer, "%s: unexpected configuration token: found: '%s', expected: '%s'",
				ERROR_PREFIX, TokenToString( parsed_token ), TokenToString( token ) );
		}
		else
		{
			sprintf( error_buffer, "%s: unknown configuration token: '%s', expected: '%s'",
				ERROR_PREFIX, ctx->token, TokenToString( token ) );
		}

		return CONFIG_PARSE_ERROR;
	}

	return 0;
}


static int ParseOneOf( ParseContext* ctx, ConfigToken* tokens, int sz )
{
	ConfigToken parsed_token = Token_Unknown;
	int i = 0;

	parsed_token = ParseToken( ctx );

	for( i = 0; i < sz; i++ )
	{
		if( parsed_token == tokens[i] ) return tokens[i];
	}

	if( parsed_token != Token_Unknown ) 
	{
		sprintf( error_buffer, "%s: unexpected configuration token: found: '%s', expected one of: %s",
				ERROR_PREFIX, TokenToString( parsed_token ), TokensToString( tokens, sz ) );
	}
	else
	{
		sprintf( error_buffer, "%s: unknown configuration token: '%s', expected one of: %s",
			ERROR_PREFIX, ctx->token, TokensToString( tokens, sz ) );
	}

	return CONFIG_PARSE_ERROR;
}

/* Read the password file and store the data in SSL_ServerParams's password field */
static int ReadPasswordFile( 	SSL_ServerParams* svr, const u_char* file )
{
	FILE* f = NULL;
	int i = 0;

	f = fopen( file, "rt" );
	if( f == NULL )
	{
		sprintf( error_buffer, "%s: failed to open a password file '%s'. Errno=%d: %s",
			ERROR_PREFIX, file, errno, strerror( errno ) );
		return CONFIG_PARSE_ERROR;
	}

	if( fgets( svr->password, sizeof( svr->password ), f ) == NULL )
	{
		sprintf( error_buffer, "%s: failed to read from a password file '%s'. Errno=%d: %s",
			ERROR_PREFIX, file, errno, strerror( errno ) );

		fclose( f );
		return CONFIG_PARSE_ERROR;
	}

	fclose( f );
	/* remove the trailing \n, if any*/
	i = strlen( svr->password );
	if( i && svr->password[i-1] == '\n' )
	{
		svr->password[i-1] = 0;
	}

	return 0;
}

static int CheckKeyFileExist( u_char* file )
{
	FILE* f = NULL;

	f = fopen( file, "rt" );
	if( f == NULL )
	{
		sprintf( error_buffer, "%s: failed to open keyfile '%s'. Errno=%d: %s",
			ERROR_PREFIX, file, errno, strerror( errno ) );
		return CONFIG_PARSE_ERROR;
	}

	fclose( f );
	return 0;
}

int AssignParam( ParseContext* ctx, ConfigToken token, u_char* val )
{
	SSL_ServerParams* svr = NULL;
	int rc = 0;

	/* get the last server */
	svr = ctx->config->server[ctx->config->server_cnt-1];
	if( svr == NULL )
	{
		sprintf( error_buffer, "%s: unexpected condition at %s:%d", ERROR_PREFIX, __FILE__, __LINE__ );
		return CONFIG_PARSE_ERROR;
	}

	switch( token )
	{
	case Token_IP:
		svr->server_ip.s_addr = inet_addr( val );
		if( INADDR_NONE == svr->server_ip.s_addr )
		{
			sprintf( error_buffer, "%s: invalid IP address format '%s'", ERROR_PREFIX, val );
			rc = CONFIG_PARSE_ERROR;
		}
		break;

	case Token_Port:
		svr->port = atoi( val );
        if ( svr->port < 0 || svr->port > MAX_PORTS ) 
        {
			sprintf( error_buffer, "%s: invalid TCP port value '%s'", ERROR_PREFIX, val );
			rc = CONFIG_PARSE_ERROR;
        }
		break;

	case Token_KeyFile:
		rc = CheckKeyFileExist( val );
		if( rc == 0 )
		{
			strncpy( svr->server_keyfile, val, strlen(val) >= MAX_PATH_LEN - 1 ? MAX_PATH_LEN - 1 : strlen(val) );
			svr->server_keyfile[MAX_PATH_LEN-1]=0;
		}
		break;

	case Token_Pwd:
        strncpy( svr->password, val, strlen(val) >= MAX_PATH_LEN - 1 ? MAX_PATH_LEN - 1 : strlen(val) );
		svr->password[MAX_PATH_LEN-1]=0;
		break;

	case Token_PwdFile:
		rc = ReadPasswordFile( svr, val );
		break;

	default:
		sprintf( error_buffer, "%s: unexpected condition at %s:%d", ERROR_PREFIX, __FILE__, __LINE__ );
		rc = CONFIG_PARSE_ERROR;
		break;
	}

	return rc;
}


static int FormatMissingServerParamError( ConfigToken token )
{
	sprintf( error_buffer, "%s: Error in server definition: parameter '%s' is missing", ERROR_PREFIX, TokenToString( token ) );
	return CONFIG_PARSE_ERROR;
}


int ParseParamGroup( ParseContext* ctx )
{
	ConfigToken ParamTokens[] = { Token_IP, Token_Port, Token_KeyFile, Token_Pwd, Token_PwdFile, Token_RightBrace };
	ConfigToken token = Token_Unknown;
	char token_checks[TOKEN_COUNT];
	int rc = 0; 

	memset( token_checks, 0, sizeof(token_checks) );

	if( MatchToken( ctx, Token_LeftBrace ) == CONFIG_PARSE_ERROR ) return CONFIG_PARSE_ERROR;

	do 
	{
		/* get the parameter */
		token = ParseOneOf( ctx, ParamTokens, ARRAY_SIZE( ParamTokens ) );
		if( token == CONFIG_PARSE_ERROR ) rc = CONFIG_PARSE_ERROR;

		if( rc == 0 && token != Token_RightBrace )
		{
			token_checks[token] = 1;
			/* get the value */
			Advance( ctx );
			if( ctx->token == NULL )
			{
				sprintf( error_buffer, "%s: unexpected EOF found near '%s'", ERROR_PREFIX, TokenToString( token ) );
				rc = CONFIG_PARSE_ERROR;
			}

			/* assign the parameter value */
			if( rc == 0 ) rc = AssignParam( ctx, token, ctx->token );
		}

	} while( rc == 0 && token != Token_RightBrace );

	if( rc == 0 ) 
	{
		/* validate the current server settings */
		if( !token_checks[Token_IP] ) rc = FormatMissingServerParamError( Token_IP );
		if( rc == 0 && !token_checks[Token_KeyFile] ) rc = FormatMissingServerParamError( Token_KeyFile );
		if( rc == 0 && !token_checks[Token_Port] ) rc = FormatMissingServerParamError( Token_Port );

		if( rc == 0 && token_checks[Token_Pwd] && token_checks[Token_PwdFile] )
		{
			sprintf( error_buffer, "%s: Error in server definition: Either 'pwdfile' (recommended) or 'pwd' parameter is expected, but not both",
					ERROR_PREFIX );
			rc = CONFIG_PARSE_ERROR;
		}
	}

	return rc;
}


int ParseServer( ParseContext* ctx )
{
	SSL_ServerParams* svr = NULL;

	/* create a new server struct */
	if( ctx->config->server_cnt >= MAX_SSL_SERVERS )
	{
		sprintf( error_buffer, "%s: maximum number of SSL server supported (%d) reached", ERROR_PREFIX, MAX_SSL_SERVERS );
		return CONFIG_PARSE_ERROR;
	}

	if( ctx->config->server_cnt < 0 ) ctx->config->server_cnt = 0;

	svr = (SSL_ServerParams*) malloc( sizeof(*svr) );
	memset( svr, 0, sizeof(*svr) );

	ctx->config->server[ctx->config->server_cnt] = svr;
	ctx->config->server_cnt++;

	return ParseParamGroup( ctx );
}


int LoadConfig( const u_char* conf, SSLConfig* cfg )
{
	ParseContext ctx;
	u_char* conf_copy = NULL;
	ConfigToken TopLevelTokens[] = { Token_Server, Token_EOF };
	ConfigToken token = Token_Unknown;

	error_buffer[0] = 0;

	conf_copy = (u_char*) malloc( strlen( conf ) + 1 );
	strcpy( conf_copy, conf );

	memset( &ctx, 0, sizeof(ctx) );
	ctx.input = conf_copy;
	ctx.config = cfg;

	do 
	{
		token = ParseOneOf( &ctx, TopLevelTokens, ARRAY_SIZE( TopLevelTokens ) );

		if( token == Token_Server ) 
		{
			if( ParseServer( &ctx ) == CONFIG_PARSE_ERROR ) token = CONFIG_PARSE_ERROR;
		}
	} while ( token == Token_Server );

	free( conf_copy ); conf_copy = ctx.input = NULL;

	/* make sure we have at least one server set up */
	if( token != CONFIG_PARSE_ERROR && ctx.config->server_cnt == 0 )
	{
		sprintf( error_buffer, "%s: at least one SSL server's configuration is expected", ERROR_PREFIX );
		token = CONFIG_PARSE_ERROR;
	}

	if( token == CONFIG_PARSE_ERROR ) 
	{
		if( strlen( error_buffer ) )
		{
			_dpd.fatalMsg( "%s(%d) => %s", *(_dpd.config_file), *(_dpd.config_line), error_buffer );
		}
		return CONFIG_PARSE_ERROR;
	}

	PrintSSLConfig( ctx.config );
	return 0;
}


/* Display the configuration for the SSL preprocessor. 
 * 
 * PARAMETERS:  None.
 *
 * RETURNS: Nothing.
 */
static void PrintSSLConfig( const SSLConfig* ssl_config )
{
	int index;

	if (ssl_config->server_cnt > 0)
	{
		_dpd.logMsg("SSL Config:\n");
		_dpd.logMsg(" Server(s):\n");

		for(index = 0; index < ssl_config->server_cnt; index++) 
		{
			_dpd.logMsg("IP address: %s\n", inet_ntoa(ssl_config->server[index]->server_ip));
			_dpd.logMsg("      Port: %i\n", ssl_config->server[index]->port);    
			_dpd.logMsg("   Keyfile: %s\n\n", ssl_config->server[index]->server_keyfile);
		}
	}
}
