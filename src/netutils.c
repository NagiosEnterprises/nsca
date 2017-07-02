/****************************************************************************
 *
 * NETUTILS.C - NSCA Network Utilities
 *
 * License: GPL
 * Copyright (c) 1999-2006 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 01-21-2006
 *
 * Description:
 *
 * This file contains common network functions used in nrpe and check_nrpe.
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
#include "../include/netutils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* opens a connection to a remote host/tcp port */
int my_tcp_connect(char *host_name,int port,int *sd){
	int result;

	result=my_connect(host_name,port,sd,"tcp");

	return result;
        }


/* opens a tcp or udp connection to a remote host */
int my_connect(char *host_name,int port,int *sd,char *proto){
	struct sockaddr_in servaddr;
	struct hostent *hp;
	struct protoent *ptrp;
	int result;
	struct addrinfo *aip = 0;
	struct addrinfo hints = {
	  (AI_V4MAPPED | AI_ADDRCONFIG),
	  AF_UNSPEC,
	};
	char server_port[32];

	/* map transport protocol name to protocol number */
	if(((ptrp=getprotobyname(proto)))==NULL){
		fprintf(stderr, "Cannot map \"%s\" to protocol number\n",proto);
		return STATE_UNKNOWN;
	        }

	hints.ai_protocol = ptrp->p_proto;
	hints.ai_socktype = (!strcmp(proto,"udp"))?SOCK_DGRAM:SOCK_STREAM;
	sprintf(server_port,"%d",port);
	result = getaddrinfo(host_name,server_port,&hints,&aip);
	if (result < 0) {
		fprintf(stderr, "Host name lookup failed: '%s'\n",host_name);
		return STATE_UNKNOWN;
		}

	/* create a socket */
	*sd=socket(aip->ai_family,aip->ai_socktype,aip->ai_protocol);
	if(*sd<0){
		fprintf(stderr, "Socket creation failed\n");
		freeaddrinfo(aip);
		return STATE_UNKNOWN;
	        }

	/* open a connection */
	result=connect(*sd,aip->ai_addr,aip->ai_addrlen);
	freeaddrinfo(aip);
	if(result<0){
		switch(errno){  
		case ECONNREFUSED:
			fprintf(stderr, "Connection refused by host\n");
			break;
		case ETIMEDOUT:
			fprintf(stderr, "Timeout while attempting connection\n");
			break;
		case ENETUNREACH:
			fprintf(stderr, "Network is unreachable\n");
			break;
		default:
			fprintf(stderr, "Connection refused or timed out\n");
		        }

		return STATE_CRITICAL;
	        }

	return STATE_OK;
        }



/* This code was taken from Fyodor's nmap utility, which was originally taken from
   the GLIBC 2.0.6 libraries because Solaris doesn't contain the inet_aton() function. */
int my_inet_aton(register const char *cp, struct in_addr *addr){
	register unsigned int val;	/* changed from u_long --david */
	register int base, n;
	register char c;
	u_int parts[4];
	register u_int *pp = parts;

	c=*cp;

	for(;;){

		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
		if (!isdigit((int)c))
			return (0);
		val=0;
		base=10;

		if(c=='0'){
			c=*++cp;
			if(c=='x'||c=='X')
				base=16,c=*++cp;
			else
				base=8;
		        }

		for(;;){
			if(isascii((int)c) && isdigit((int)c)){
				val=(val*base)+(c -'0');
				c=*++cp;
			        } 
			else if(base==16 && isascii((int)c) && isxdigit((int)c)){
				val=(val<<4) | (c+10-(islower((int)c)?'a':'A'));
				c = *++cp;
			        } 
			else
				break;
		        }

		if(c=='.'){

			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16 bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if(pp>=parts+3)
				return (0);
			*pp++=val;
			c=*++cp;
		        } 
		else
			break;
	        }

	/* Check for trailing characters */
	if(c!='\0' && (!isascii((int)c) || !isspace((int)c)))
		return (0);

	/* Concoct the address according to the number of parts specified */
	n=pp-parts+1;
	switch(n){

	case 0:
		return (0);		/* initial nondigit */

	case 1:				/* a -- 32 bits */
		break;

	case 2:				/* a.b -- 8.24 bits */
		if(val>0xffffff)
			return (0);
		val|=parts[0]<<24;
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		if(val>0xffff)
			return (0);
		val|=(parts[0]<< 24) | (parts[1]<<16);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		if(val>0xff)
			return (0);
		val|=(parts[0]<<24) | (parts[1]<<16) | (parts[2]<<8);
		break;
	        }

	if(addr)
		addr->s_addr=htonl(val);

	return (1);
        }



/* sends all data - thanks to Beej's Guide to Network Programming */
int sendall(int s, char *buf, int *len){
	int total=0;
	int bytesleft=*len;
	int n=0;

	while(total<*len){
		n=send(s,buf+total,bytesleft,0);
		if(n==-1)
			break;
		total+=n;
		bytesleft-=n;
	        }

	/* return number of bytes actually send here */
	*len=total;

	/* return -1 on failure, 0 on success */
	return n==-1?-1:0;
        }


/* receives all data - modelled after sendall() */
int recvall(int s, char *buf, int *len, int timeout){
	int total=0;
	int bytesleft=*len;
	int n=0;
	time_t start_time;
	time_t current_time;
	
	/* clear the receive buffer */
	bzero(buf,*len);

	time(&start_time);

	/* receive all data */
	while(total<*len){

		/* receive some data */
		n=recv(s,buf+total,bytesleft,0);

		/* no data has arrived yet (non-blocking socket) */
		if(n==-1 && errno==EAGAIN){
			time(&current_time);
			if(current_time-start_time>timeout)
				break;
			sleep(1);
			continue;
		        }

		/* receive error or client disconnect */
		else if(n<=0)
			break;

		/* apply bytes we received */
		total+=n;
		bytesleft-=n;
	        }

	/* return number of bytes actually received here */
	*len=total;

	/* return <=0 on failure, bytes received on success */
	return (n<=0)?n:total;
        }
