/****************************************************************************
 *
 * UTILS.C - Utility functions for NSCA
 * Copyright (c) 2000-2001 Ethan Galstad (nagios@nagios.org)
 * License: GPL
 * Last Modified: 06-23-2001
 *
 * Description:
 *
 * This file contains common unctions used in nsca and send_nsca
 *
 * License Information:
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
 *
 ****************************************************************************/

#include "../common/common.h"
#include "utils.h"


static unsigned long crc32_table[256];


#ifdef HAVE_LIBMCRYPT
MCRYPT td;
char *key;
char block_buffer;
char *IV;
int blocksize=1;                   /* block size = 1 byte w/ CFB mode */
int keysize=7;                     /* default to 56 bit key length */
char *mcrypt_algorithm="unknown";
char *mcrypt_mode="cfb";           /* CFB = 8-bit cipher-feedback mode */
#endif



/* build the crc table - must be called before calculating the crc value */
void generate_crc32_table(void){
	unsigned long crc, poly;
	int i, j;

	poly=0xEDB88320L;
	for(i=0;i<256;i++){
		crc=i;
		for(j=8;j>0;j--){
			if(crc & 1)
				crc=(crc>>1)^poly;
			else
				crc>>=1;
		        }
		crc32_table[i]=crc;
                }

	return;
        }


/* calculates the CRC 32 value for a buffer */
unsigned long calculate_crc32(char *buffer, int buffer_size){
	register unsigned long crc;
	int this_char;
	int current_index;

	crc=0xFFFFFFFF;

	for(current_index=0;current_index<buffer_size;current_index++){
		this_char=(int)buffer[current_index];
		crc=((crc>>8) & 0x00FFFFFF) ^ crc32_table[(crc ^ this_char) & 0xFF];
	        }

	return (crc ^ 0xFFFFFFFF);
        }



/* initializes encryption routines */
int encrypt_init(char *password,int encryption_method){
#ifdef HAVE_LIBMCRYPT
	int i;
	int iv_size;
#endif

	/* XOR or no encryption */
	if(encryption_method==ENCRYPT_NONE || encryption_method==ENCRYPT_XOR)
		return OK;

#ifdef HAVE_LIBMCRYPT

	/* get the name of the mcrypt encryption algorithm to use */
	switch(encryption_method){
	case ENCRYPT_DES:
		mcrypt_algorithm=MCRYPT_DES;
		break;
	case ENCRYPT_3DES:
		mcrypt_algorithm=MCRYPT_3DES;
		break;
	case ENCRYPT_CAST128:
		mcrypt_algorithm=MCRYPT_CAST_128;
		break;
	case ENCRYPT_CAST256:
		mcrypt_algorithm=MCRYPT_CAST_256;
		break;
	case ENCRYPT_XTEA:
		mcrypt_algorithm=MCRYPT_XTEA;
		break;
	case ENCRYPT_3WAY:
		mcrypt_algorithm=MCRYPT_3WAY;
		break;
	case ENCRYPT_BLOWFISH:
		mcrypt_algorithm=MCRYPT_BLOWFISH;
		break;
	case ENCRYPT_TWOFISH:
		mcrypt_algorithm=MCRYPT_TWOFISH;
		break;
	case ENCRYPT_LOKI97:
		mcrypt_algorithm=MCRYPT_LOKI97;
		break;
	case ENCRYPT_RC2:
		mcrypt_algorithm=MCRYPT_RC2;
		break;
	case ENCRYPT_ARCFOUR:
		mcrypt_algorithm=MCRYPT_ARCFOUR;
		break;
	case ENCRYPT_RIJNDAEL128:
		mcrypt_algorithm=MCRYPT_RIJNDAEL_128;
		break;
	case ENCRYPT_RIJNDAEL192:
		mcrypt_algorithm=MCRYPT_RIJNDAEL_192;
		break;
	case ENCRYPT_RIJNDAEL256:
		mcrypt_algorithm=MCRYPT_RIJNDAEL_256;
		break;
	case ENCRYPT_WAKE:
		mcrypt_algorithm=MCRYPT_WAKE;
		break;
	case ENCRYPT_SERPENT:
		mcrypt_algorithm=MCRYPT_SERPENT;
		break;
	case ENCRYPT_ENIGMA:
		mcrypt_algorithm=MCRYPT_ENIGMA;
		break;
	case ENCRYPT_GOST:
		mcrypt_algorithm=MCRYPT_GOST;
		break;
	case ENCRYPT_SAFER64:
		mcrypt_algorithm=MCRYPT_SAFER_SK64;
		break;
	case ENCRYPT_SAFER128:
		mcrypt_algorithm=MCRYPT_SAFER_SK128;
		break;
	case ENCRYPT_SAFERPLUS:
		mcrypt_algorithm=MCRYPT_SAFERPLUS;
		break;

	default:
		mcrypt_algorithm="unknown";
		break;
	        }

	/* open encryption module */
	if((td=mcrypt_module_open(mcrypt_algorithm,NULL,mcrypt_mode,NULL))==MCRYPT_FAILED){
		syslog(LOG_ERR,"Could not open mcrypt algorithm '%s' with mode '%s'",mcrypt_algorithm,mcrypt_mode);
		return ERROR;
	        }

#ifdef DEBUG
	syslog(LOG_INFO,"Using '%s' as crypto algorithm...",mcrypt_algorithm);
#endif

	/* allocate memory for IV buffer */
	iv_size=mcrypt_enc_get_iv_size(td);
	if((IV=(char *)malloc(iv_size))==NULL){
		syslog(LOG_ERR,"Could not allocate memory for IV buffer");
		return ERROR;
	        }

	/* fill IV buffer with random data - this isn't too random, and should be improved */
	srand(time(NULL));
	for(i=0;i<iv_size;i++)
		IV[i]=rand();

	/* get maximum key size for this algorithm */
	keysize=mcrypt_enc_get_key_size(td);

	/* generate an encryption/decription key using the password */
	if((key=(char *)malloc(keysize))==NULL){
		syslog(LOG_ERR,"Could not allocate memory for encryption/decryption key");
		return ERROR;
	        }
	bzero(key,keysize);

	if(keysize<strlen(password))
		strncpy(key,password,keysize);
	else
		strncpy(key,password,strlen(password));
	
	/* initialize encryption buffers */
	mcrypt_generic_init(td,key,keysize,IV);

#endif

	return OK;
        }



/* encryption routine cleanup */
void encrypt_cleanup(int encryption_method){

	/* XOR or no encryption */
	if(encryption_method==ENCRYPT_NONE || encryption_method==ENCRYPT_XOR)
		return;

#ifdef HAVE_LIBMCRYPT
	/* mcrypt cleanup */
	mcrypt_generic_end(td);
#endif

	return;
        }



/* encrypt a buffer */
void encrypt_buffer(char *buffer,int buffer_size, char *password, int encryption_method){
	int x;
	int y;
	int password_length;

	/* no encryption */
	if(encryption_method==ENCRYPT_NONE)
		return;

	/* simple XOR "encryption" - not meant for any real security, just obfuscates data, but its fast... */
	else if(encryption_method==ENCRYPT_XOR){

		password_length=strlen(password);

		for(y=0,x=0;y<buffer_size;y++,x++){

			/* keep rotating over password */
			if(x>=password_length)
				x=0;

			buffer[y]^=password[x];
	                }
		return;
	        }

#ifdef HAVE_LIBMCRYPT
	/* use mcrypt routines */
	else{

		/* encrypt each byte of buffer, one byte at a time (CFB mode) */
		for(x=0;x<buffer_size;x++)
			mcrypt_generic(td,&buffer[x],1);
	        }
#endif

	return;
        }


/* decrypt a buffer */
void decrypt_buffer(char *buffer,int buffer_size, char *password, int encryption_method){
	int x=0;

	/* no encryption */
	if(encryption_method==ENCRYPT_NONE)
		return;

	/* XOR decryption is the same as encryption */
	else if(encryption_method==ENCRYPT_XOR){
		encrypt_buffer(buffer,buffer_size,password,encryption_method);
		return;
	        }

#ifdef HAVE_LIBMCRYPT
	/* use mcrypt routines */
	else{

		/* encrypt each byte of buffer, one byte at a time (CFB mode) */
		for(x=0;x<buffer_size;x++)
			mdecrypt_generic(td,&buffer[x],1);
	        }
#endif

	return;
        }


/* fill a buffer with semi-random data */
void randomize_buffer(char *buffer,int buffer_size){
	int x;

	/* seed the random number generator */
	srand(time(NULL));

	/* use numbers and alpha characters */
	for(x=0;x<buffer_size;x++)
		buffer[x]=(int)'0'+(int)(72.0*rand()/(RAND_MAX+1.0));

	return;
        }


/* strips trailing newlines, carriage returns, spaces, and tabs from a string */
void strip(char *buffer){
	int x;
	int index;

	for(x=strlen(buffer);x>=1;x--){
		index=x-1;
		if(buffer[index]==' ' || buffer[index]=='\r' || buffer[index]=='\n' || buffer[index]=='\t')
			buffer[index]='\x0';
		else
			break;
	        }

	return;
        }
