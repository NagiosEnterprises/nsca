/*********************************************************************************
 *
 * UTILS.H - Header file for NSCA utility functions
 * License: GPL
 * Copyright (c) 2000-2001 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 07-23-2001
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

#include "../common/config.h"

void generate_crc32_table(void);
unsigned long calculate_crc32(char *, int);

int encrypt_init(char *,int);
void encrypt_cleanup(int);

void encrypt_buffer(char *,int,char *,int);
void decrypt_buffer(char *,int,char *,int);

void randomize_buffer(char *,int);

void strip(char *);

#endif



