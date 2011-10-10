/*********************************************************************************
 *
 * UTILS.H - Header file for NSCA utility functions
 *
 * License: GPL
 * Copyright (c) 2000-2003 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 10-15-2003
 *
 * Description:
 *
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
 ********************************************************************************/

#ifndef _UTILS_H
#define _UTILS_H

#include "config.h"

struct crypt_instance {
	char transmitted_iv[TRANSMITTED_IV_SIZE];
#ifdef HAVE_LIBMCRYPT
	MCRYPT td;
	char *key;
	char *IV;
	char block_buffer;
	int blocksize;
	int keysize;
	char *mcrypt_algorithm;
	char *mcrypt_mode;
#endif
        };

char *escape_newlines(char *);
void generate_crc32_table(void);
unsigned long calculate_crc32(char *, int);

int encrypt_init(char *,int,char *,struct crypt_instance **);
void encrypt_cleanup(int,struct crypt_instance *);

static void generate_transmitted_iv(char *transmitted_iv);

void encrypt_buffer(char *,int,char *,int,struct crypt_instance *);
void decrypt_buffer(char *,int,char *,int,struct crypt_instance *);

void randomize_buffer(char *,int);

void strip(char *);

void clear_buffer(char *,int);

void display_license(void);

#endif



