/************************************************************************
 *
 * COMMON.H - NSCA Common Include File
 * Copyright (c) 1999-2001 Ethan Galstad (nagios@nagios.org)
 * Last Modified: 06-23-2001
 *
 * License:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 ************************************************************************/

#include "config.h"


#define OK		0
#define ERROR		-1

#define TRUE		1
#define FALSE		0

#define	STATE_CRITICAL 	2	/* service state return codes */
#define STATE_WARNING 	1
#define STATE_OK       	0
#define STATE_UNKNOWN  	-1


#define DEFAULT_SOCKET_TIMEOUT	10	/* timeout after 10 seconds */
#define DEFAULT_SERVER_PORT	5667	/* default port to use */

#define MAX_INPUT_BUFFER	2048	/* max size of most buffers we use */

#define MAX_HOST_ADDRESS_LENGTH	256	/* max size of a host address */

#define MAX_HOSTNAME_LENGTH	64
#define MAX_DESCRIPTION_LENGTH	128
#define MAX_PLUGINOUTPUT_LENGTH	512


/********************* ENCRYPTION TYPES ****************/

#define ENCRYPT_NONE            0       /* no encryption */
#define ENCRYPT_XOR             1       /* not really encrypted, just obfuscated */

#ifdef HAVE_LIBMCRYPT
#define ENCRYPT_DES             2       /* DES */
#define ENCRYPT_3DES            3       /* 3DES or Triple DES */
#define ENCRYPT_CAST128         4       /* CAST-128 */
#define ENCRYPT_CAST256         5       /* CAST-256 */
#define ENCRYPT_XTEA            6       /* xTEA */
#define ENCRYPT_3WAY            7       /* 3-WAY */
#define ENCRYPT_BLOWFISH        8       /* SKIPJACK */
#define ENCRYPT_TWOFISH         9       /* TWOFISH */
#define ENCRYPT_LOKI97          10      /* LOKI97 */
#define ENCRYPT_RC2             11      /* RC2 */
#define ENCRYPT_ARCFOUR         12      /* RC4 */
#define ENCRYPT_RC6             13      /* RC6 */            /* UNUSED */
#define ENCRYPT_RIJNDAEL128     14      /* RIJNDAEL-128 */
#define ENCRYPT_RIJNDAEL192     15      /* RIJNDAEL-192 */
#define ENCRYPT_RIJNDAEL256     16      /* RIJNDAEL-256 */
#define ENCRYPT_MARS            17      /* MARS */           /* UNUSED */
#define ENCRYPT_PANAMA          18      /* PANAMA */         /* UNUSED */
#define ENCRYPT_WAKE            19      /* WAKE */
#define ENCRYPT_SERPENT         20      /* SERPENT */
#define ENCRYPT_IDEA            21      /* IDEA */           /* UNUSED */
#define ENCRYPT_ENIGMA          22      /* ENIGMA (Unix crypt) */
#define ENCRYPT_GOST            23      /* GOST */
#define ENCRYPT_SAFER64         24      /* SAFER-sk64 */
#define ENCRYPT_SAFER128        25      /* SAFER-sk128 */
#define ENCRYPT_SAFERPLUS       26      /* SAFER+ */
#endif


/**************** PACKET STRUCTURE DEFINITION **********/

#define NSCA_PACKET_VERSION_1	1		/* packet version identifier (in case packet type changes in future versions) */

typedef struct packet_struct{
	int       packet_version;
	unsigned long       crc32_value;
	char      host_name[MAX_HOSTNAME_LENGTH];
	char      svc_description[MAX_DESCRIPTION_LENGTH];
	int       return_code;
	char      plugin_output[MAX_PLUGINOUTPUT_LENGTH];
        }packet;



