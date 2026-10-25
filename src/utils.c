/****************************************************************************
 *
 * UTILS.C - Utility functions for NSCA
 *
 * License: GPL
 * Copyright (c) 2000-2008 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 01-15-2008
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

#include "../include/common.h"
#include "../include/utils.h"


/*#define DEBUG*/

static unsigned long crc32_table[256];
static void generate_transmitted_iv(char *transmitted_iv);

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



#ifdef HAVE_LIBGCRYPT
/* maps an NSCA encryption method to a libgcrypt cipher.  the key size is the one libmcrypt used for the
   algorithm, since the password is zero-padded/truncated to that length - keeping it identical keeps us
   wire-compatible with clients and daemons that were built against libmcrypt */
static int get_gcrypt_cipher(int encryption_method, int *algo, int *keysize, const char **name){

        switch(encryption_method){
        case ENCRYPT_DES:
                *algo=GCRY_CIPHER_DES;
                *keysize=8;
                *name="DES";
                break;
        case ENCRYPT_3DES:
                *algo=GCRY_CIPHER_3DES;
                *keysize=24;
                *name="3DES";
                break;
        case ENCRYPT_CAST128:
                *algo=GCRY_CIPHER_CAST5;
                *keysize=16;
                *name="CAST-128";
                break;
        case ENCRYPT_BLOWFISH:
                *algo=GCRY_CIPHER_BLOWFISH;
                *keysize=56;
                *name="BLOWFISH";
                break;
        case ENCRYPT_TWOFISH:
                *algo=GCRY_CIPHER_TWOFISH;
                *keysize=32;
                *name="TWOFISH";
                break;
        case ENCRYPT_RIJNDAEL128:
                /* RIJNDAEL-128 with libmcrypt's 32 byte key is AES-256 */
                *algo=GCRY_CIPHER_AES256;
                *keysize=32;
                *name="RIJNDAEL-128";
                break;
        case ENCRYPT_SERPENT:
                *algo=GCRY_CIPHER_SERPENT256;
                *keysize=32;
                *name="SERPENT";
                break;
        default:
                return ERROR;
                }

        return OK;
        }


/* returns TRUE if the encryption method can be used with this build */
int encrypt_method_supported(int encryption_method){
        int algo;
        int keysize;
        const char *name;

        if(encryption_method==ENCRYPT_NONE || encryption_method==ENCRYPT_XOR)
                return TRUE;

        return (get_gcrypt_cipher(encryption_method,&algo,&keysize,&name)==OK)?TRUE:FALSE;
        }
#else
/* returns TRUE if the encryption method can be used with this build */
int encrypt_method_supported(int encryption_method){

        return (encryption_method==ENCRYPT_NONE || encryption_method==ENCRYPT_XOR)?TRUE:FALSE;
        }
#endif


/* initializes encryption routines */
int encrypt_init(char *password,int encryption_method,char *received_iv,struct crypt_instance **CIptr){
#ifdef HAVE_LIBGCRYPT
        int algo;
        size_t iv_size;
        size_t password_length;
        gcry_error_t err;
#endif
        struct crypt_instance *CI;

        CI=malloc(sizeof(struct crypt_instance));
        *CIptr=CI;

        if(CI==NULL){
                syslog(LOG_ERR, "Could not allocate memory for crypt instance");
                return ERROR;
                }

	/* server generates IV used for encryption */
        if(received_iv==NULL)
                generate_transmitted_iv(CI->transmitted_iv);

	/* client receives IV from server */
        else
                memcpy(CI->transmitted_iv,received_iv,TRANSMITTED_IV_SIZE);

#ifdef HAVE_LIBGCRYPT
        CI->hd_open=FALSE;                      /* nothing to clean up until the cipher is opened */
        CI->key=NULL;
        CI->keysize=0;
        CI->algorithm_name="unknown";
#endif

        /* XOR or no encryption */
        if(encryption_method==ENCRYPT_NONE || encryption_method==ENCRYPT_XOR)
                return OK;

#ifdef HAVE_LIBGCRYPT

        /* libgcrypt must be initialized before any other call is made into it */
        if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)){
                if(gcry_check_version(NSCA_GCRYPT_MIN_VERSION)==NULL){
                        syslog(LOG_ERR,"libgcrypt is too old (need %s or newer)",NSCA_GCRYPT_MIN_VERSION);
                        encrypt_cleanup(encryption_method,CI);
                        *CIptr=NULL;
                        return ERROR;
                        }
                /* we keep the key in ordinary memory and wipe it ourselves on cleanup */
                gcry_control(GCRYCTL_DISABLE_SECMEM,0);
                gcry_control(GCRYCTL_INITIALIZATION_FINISHED,0);
                }

        /* get the libgcrypt cipher to use */
        if(get_gcrypt_cipher(encryption_method,&algo,&CI->keysize,&CI->algorithm_name)==ERROR){
                syslog(LOG_ERR,"Encryption method %d is not supported",encryption_method);
                encrypt_cleanup(encryption_method,CI);
                *CIptr=NULL;
                return ERROR;
                }

#ifdef DEBUG
        syslog(LOG_INFO,"Attempting to initialize '%s' crypto algorithm...",CI->algorithm_name);
#endif

        /* open the cipher in 8-bit cipher-feedback mode (what libmcrypt called "cfb") */
        if((err=gcry_cipher_open(&CI->hd,algo,GCRY_CIPHER_MODE_CFB8,0))!=0){
                syslog(LOG_ERR,"Could not open crypto algorithm '%s': %s",CI->algorithm_name,gcry_strerror(err));
                encrypt_cleanup(encryption_method,CI);
                *CIptr=NULL;
                return ERROR;
                }
        CI->hd_open=TRUE;

#ifdef DEBUG
        syslog(LOG_INFO,"Using '%s' as crypto algorithm...",CI->algorithm_name);
#endif

        /* the IV is the first bytes of the IV the server transmitted, one cipher block long */
        iv_size=gcry_cipher_get_algo_blklen(algo);
        if(iv_size==0 || iv_size>TRANSMITTED_IV_SIZE){
                syslog(LOG_ERR,"IV size for crypto algorithm exceeds limits");
                encrypt_cleanup(encryption_method,CI);
                *CIptr=NULL;
                return ERROR;
                }

        /* generate an encryption/description key using the password */
        if((CI->key=(char *)calloc(1,CI->keysize))==NULL){
                syslog(LOG_ERR,"Could not allocate memory for encryption/decryption key");
                encrypt_cleanup(encryption_method,CI);
                *CIptr=NULL;
                return ERROR;
                }

        password_length=strlen(password);
        memcpy(CI->key,password,(password_length<(size_t)CI->keysize)?password_length:(size_t)CI->keysize);

        /* libmcrypt accepted weak DES/3DES keys (e.g. a short password zero-padded to 24 bytes), so we must too */
        gcry_cipher_ctl(CI->hd,GCRYCTL_SET_ALLOW_WEAK_KEY,NULL,1);

        err=gcry_cipher_setkey(CI->hd,CI->key,CI->keysize);
        if(err!=0 && gcry_err_code(err)!=GPG_ERR_WEAK_KEY){
                syslog(LOG_ERR,"Could not set key for crypto algorithm '%s': %s",CI->algorithm_name,gcry_strerror(err));
                encrypt_cleanup(encryption_method,CI);
                *CIptr=NULL;
                return ERROR;
                }

        if((err=gcry_cipher_setiv(CI->hd,CI->transmitted_iv,iv_size))!=0){
                syslog(LOG_ERR,"Could not set IV for crypto algorithm '%s': %s",CI->algorithm_name,gcry_strerror(err));
                encrypt_cleanup(encryption_method,CI);
                *CIptr=NULL;
                return ERROR;
                }
#endif

        return OK;
        }



/* encryption routine cleanup */
void encrypt_cleanup(int encryption_method, struct crypt_instance *CI){

	/* no crypt instance */
	if(CI==NULL)
		return;

#ifdef HAVE_LIBGCRYPT
        /* libgcrypt cleanup */
        if(encryption_method!=ENCRYPT_NONE && encryption_method!=ENCRYPT_XOR){
		if(CI->hd_open==TRUE){
			gcry_cipher_close(CI->hd);
			CI->hd_open=FALSE;
			}
		if(CI->key!=NULL)
			clear_buffer(CI->key,CI->keysize);
		free(CI->key);
		CI->key=NULL;
		}
#endif

        free(CI);

        return;
        }



/* generates IV to use for encrypted communications (function is called by server only, client uses IV it receives from server) */
static void generate_transmitted_iv(char *transmitted_iv){
        FILE *fp;
        int x;
        int seed=0;
        size_t nread=0;

        /*********************************************************/
        /* fill IV buffer with data that's as random as possible */
        /*********************************************************/

        /* try to read the IV directly from /dev/urandom, as its a much better source of entropy than seeding rand() */
        fp=fopen("/dev/urandom","r");
        if(fp!=NULL){
                nread=fread(transmitted_iv,1,TRANSMITTED_IV_SIZE,fp);
                fclose(fp);
                }

        /* got all the random bytes we needed straight from the kernel CSPRNG */
        if(nread==TRANSMITTED_IV_SIZE)
                return;

        /* fallback: /dev/urandom unavailable or short read, so seed rand() as well as we can and fill in the rest */
        fp=fopen("/dev/urandom","r");
        if(fp!=NULL){
                if(fread(&seed,1,sizeof(seed),fp)!=sizeof(seed))
                        seed=(int)time(NULL);
                fclose(fp);
                }
        else
                seed=(int)time(NULL);

        /* generate pseudo-random IV for any bytes we weren't able to read above */
        srand(seed);
        for(x=(int)nread;x<TRANSMITTED_IV_SIZE;x++)
                transmitted_iv[x]=(int)((256.0*rand())/(RAND_MAX+1.0));

        return;
        }



/* encrypt a buffer */
void encrypt_buffer(char *buffer,int buffer_size, char *password, int encryption_method, struct crypt_instance *CI){
        int x;
        int y;
        int password_length;

#ifdef DEBUG
        syslog(LOG_INFO,"Encrypting with algorithm #%d",encryption_method);
#endif

	/* no crypt instance */
	if(CI==NULL)
		return;

        /* no encryption */
        if(encryption_method==ENCRYPT_NONE)
                return;

        /* simple XOR "encryption" - not meant for any real security, just obfuscates data, but its fast... */
        else if(encryption_method==ENCRYPT_XOR){

                /* rotate over IV we received from the server... */
                for(y=0,x=0;y<buffer_size;y++,x++){

                        /* keep rotating over IV */
                        if(x>=TRANSMITTED_IV_SIZE)
                                x=0;

                        buffer[y]^=CI->transmitted_iv[x];
                        }

                /* rotate over password... */
                password_length=strlen(password);
                for(y=0,x=0;y<buffer_size;y++,x++){

                        /* keep rotating over password */
                        if(x>=password_length)
                                x=0;

                        buffer[y]^=password[x];
                        }

                return;
                }

#ifdef HAVE_LIBGCRYPT
        /* use libgcrypt routines (CFB-8 encrypts in place, byte by byte) */
        else if(CI->hd_open==TRUE)
                gcry_cipher_encrypt(CI->hd,buffer,buffer_size,NULL,0);
#endif

        return;
        }


/* decrypt a buffer */
void decrypt_buffer(char *buffer,int buffer_size, char *password, int encryption_method, struct crypt_instance *CI){
#ifdef DEBUG
        syslog(LOG_INFO,"Decrypting with algorithm #%d",encryption_method);
#endif

	/* no crypt instance */
	if(CI==NULL)
		return;

        /* no encryption */
        if(encryption_method==ENCRYPT_NONE)
                return;

        /* XOR "decryption" is the same as encryption */
        else if(encryption_method==ENCRYPT_XOR)
                encrypt_buffer(buffer,buffer_size,password,encryption_method,CI);

#ifdef HAVE_LIBGCRYPT
        /* use libgcrypt routines (CFB-8 decrypts in place, byte by byte) */
        else if(CI->hd_open==TRUE)
                gcry_cipher_decrypt(CI->hd,buffer,buffer_size,NULL,0);
#endif

        return;
        }



/* fill a buffer with semi-random data */
void randomize_buffer(char *buffer,int buffer_size){
	FILE *fp;
	int x;
	int seed;

	/**** FILL BUFFER WITH RANDOM ALPHA-NUMERIC CHARACTERS ****/

	/***************************************************************
	   Only use alpha-numeric characters because plugins usually
	   only generate numbers and letters in their output.  We
	   want the buffer to contain the same set of characters as
	   plugins, so its harder to distinguish where the real output
	   ends and the rest of the buffer (padded randomly) starts.
	***************************************************************/

	/* try to get seed value from /dev/urandom, as its a better source of entropy */
	fp=fopen("/dev/urandom","r");
	if(fp!=NULL){
		if(fread(&seed,1,sizeof(seed),fp)!=sizeof(seed))
			seed=(int)time(NULL);
		fclose(fp);
	        }

	/* else fallback to using the current time as the seed */
	else
		seed=(int)time(NULL);

	srand(seed);
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



/* wipes an area of memory clean */
void clear_buffer(char *buffer, int buffer_length){

	/* NULL all bytes of buffer */
	memset(buffer,'\x0',buffer_length);

	return;
        }



/* show license */
void display_license(void){

	printf("This program is free software; you can redistribute it and/or modify\n");
	printf("it under the terms of the GNU General Public License as published by\n");
	printf("the Free Software Foundation; either version 2 of the License, or\n");
	printf("(at your option) any later version.\n\n");
	printf("This program is distributed in the hope that it will be useful,\n");
	printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	printf("GNU General Public License for more details.\n\n");
	printf("You should have received a copy of the GNU General Public License\n");
	printf("along with this program; if not, write to the Free Software\n");
	printf("Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n");

	return;
        }
