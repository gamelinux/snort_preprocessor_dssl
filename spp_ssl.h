
#ifndef SPP_SSL_H
#define SPP_SSL_H

#ifdef WIN32
	#pragma warning(push, 3)
	#include <pcap.h>
	#pragma warning(pop)
#else
	#include <pcap.h> 
#endif

#ifdef __linux
	#include <arpa/inet.h>
#endif

#include <openssl/ssl.h>
#include <dssl/sslcap.h>

#define MAX_PORTS 65536

/* 
The original PKT_REBUILT_STREAM defenition is in decode.h, which seems to be incompatible 
with sf_snort_packet.h, so we redefine it here.
*/
#define PKT_REBUILT_STREAM	0x00000002

/* Default SSL port */
#define SSL_PORT    443

/* CapEnv buffer length */
#define MAX_CAPENV_BUF	   1024
#define MAX_SSL_SERVERS    100
#define MAX_PATH_LEN 255

/*
 * Global SSL preprocessor configuration.
 */


typedef struct _SSL_ServerParams
{
  struct in_addr    server_ip;
  uint16_t          port;  
  char				server_certfile[MAX_PATH_LEN];
  char				server_keyfile[MAX_PATH_LEN];
  char				password[MAX_PATH_LEN];
} SSL_ServerParams;


typedef struct _SSLConfig
{
    int                server_cnt;
	SSL_ServerParams*  server[MAX_SSL_SERVERS];
} SSLConfig;


/* Prototypes for public interface */
extern void SetupSSL();

void ParseSSLArgs( u_char*, SSLConfig* ssl_config );

struct _SFSnortPacket;
extern struct _SFSnortPacket*	current_snort_packet;

/* print macros */
//#define _PRINT_LOG    _dpd.logMsg
#define _PRINT_LOG		printf
//#define _PRINT_FATAL	_dpd.fatalMsg
#define _PRINT_FATAL	printf

#endif /* SPP_SSL_H */
