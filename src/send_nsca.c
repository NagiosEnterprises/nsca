/**********************************************************************************
 *
 * SEND_NSCA.C - NSCA Client
 * Version: 1.2
 * License: GPL
 * Copyright (c) 2000-2001 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 06-23-2001
 *
 * Command line: SEND_NSCA <host_address> [-p port] [-to to_sec] [-c config_file]
 *
 * Description:
 *
 *
 *********************************************************************************/

#include "../common/common.h"
#include "../common/config.h"
#include "netutils.h"
#include "utils.h"

#define PROGRAM_VERSION "1.2"
#define MODIFICATION_DATE "06-23-2001"

time_t start_time,end_time;

int server_port=DEFAULT_SERVER_PORT;
char server_name[MAX_HOST_ADDRESS_LENGTH];
char password[MAX_INPUT_BUFFER]="";
char config_file[MAX_INPUT_BUFFER]="send_nsca.cfg";
char delimiter[2]="\t";

int socket_timeout=DEFAULT_SOCKET_TIMEOUT;

int warning_time=0;
int check_warning_time=FALSE;
int critical_time=0;
int check_critical_time=FALSE;
int encryption_method=ENCRYPT_XOR;


int process_arguments(int,char **);
int read_config_file(char *);
void alarm_handler(int);




int main(int argc, char **argv){
	int sd;
	int rc;
	int result;
	packet send_packet;
	packet receive_packet;
	char input_buffer[MAX_INPUT_BUFFER];
	char *temp_ptr;
	char host_name[MAX_HOSTNAME_LENGTH];
	char svc_description[MAX_DESCRIPTION_LENGTH];
	char plugin_output[MAX_PLUGINOUTPUT_LENGTH];
	int return_code;
	int total_packets=0;
	unsigned long calculated_crc32=0L;

	result=process_arguments(argc,argv);

	if(result!=OK){

		printf("Incorrect command line arguments supplied\n");
		printf("\n");
		printf("NSCA Client %s\n",PROGRAM_VERSION);
		printf("Copyright (c) 2000-2001 Ethan Galstad (nagios@nagios.org)\n");
		printf("Last Modified: %s\n",MODIFICATION_DATE);
		printf("License: GPL\n");
		printf("Encryption Routines: ");
#ifdef HAVE_LIBMCRYPT
		printf("AVAILABLE");
#else
		printf("NOT AVAILABLE");
#endif		
		printf("\n");
		printf("\n");
		printf("Usage: %s <host_address> [-p port] [-to to_sec] [-d delim] [-c config_file]\n",argv[0]);
		printf("\n");
		printf("Options:\n");
		printf(" <host_address> = The IP address of the host running the NSCA daemon\n");
		printf(" [port]         = The port on which the daemon is running - default is %d\n",DEFAULT_SERVER_PORT);
		printf(" [to_sec]       = Number of seconds before connection attempt times out.\n");
		printf("                  (default timeout is %d seconds)\n",DEFAULT_SOCKET_TIMEOUT);
		printf(" [delim]        = Delimiter to use when parsing input (defaults to a tab)\n");
		printf(" [config_file]  = Name of config file to use\n");
		printf("\n");
		printf("Note:\n");
		printf("This utility is used to send passive service check results to the NSCA daemon.\n");
		printf("Servce check data that is to be sent to the NSCA daemon is read from standard\n");
		printf("input. Service check information is in the following format (tab-delimited\n");
		printf("unless overriden with -d command line argument, one entry per line):\n");
		printf("\n");
		printf("<host_name>[tab]<svc_description>[tab]<return_code>[tab]<plugin_output>[newline]\n");
		printf("\n");

		return STATE_UNKNOWN;
	        }

	/* read the config file */
	result=read_config_file(config_file);	

	/* exit if there are errors... */
	if(result==ERROR){
		printf("Error: Config file '%s' contained errors...",config_file);
		return STATE_CRITICAL;
		}

	/* generate the CRC 32 table */
	generate_crc32_table();

	/* initialize encryption/decryption routines */
	if(encrypt_init(password,encryption_method)!=OK){
		printf("Error: Failed to initialize encryption libraries for method %d\n",encryption_method);
		return STATE_CRITICAL;
	        }

	/* initialize alarm signal handling */
	signal(SIGALRM,alarm_handler);

	/* set socket timeout */
	alarm(socket_timeout);

	time(&start_time);

	/* try to connect to the host at the given port number */
	result=my_tcp_connect(server_name,server_port,&sd);

	/* we connected! */
	if(result==STATE_OK){

		/* read all data from STDIN until there isn't anymore */
		while(fgets(input_buffer,sizeof(input_buffer)-1,stdin)){

			if(feof(stdin))
				break;

			strip(input_buffer);

			if(!strcmp(input_buffer,""))
				continue;

			/* get the host name */
			temp_ptr=strtok(input_buffer,delimiter);
			if(temp_ptr==NULL){
				printf("Error: Host name is NULL!\n");
				continue;
			        }
			strncpy(host_name,temp_ptr,sizeof(host_name)-1);
			host_name[sizeof(host_name)-1]='\x0';

			/* get the service description */
			temp_ptr=strtok(NULL,delimiter);
			if(temp_ptr==NULL){
				printf("Error: Service description is NULL!\n");
				continue;
			        }
			strncpy(svc_description,temp_ptr,sizeof(svc_description)-1);
			svc_description[sizeof(svc_description)-1]='\x0';

			/* get the return code */
			temp_ptr=strtok(NULL,delimiter);
			if(temp_ptr==NULL){
				printf("Error: Return code is NULL!\n");
				continue;
			        }
			return_code=atoi(temp_ptr);

			/* get the plugin output */
			temp_ptr=strtok(NULL,"\n");
			if(temp_ptr==NULL){
				printf("Error: Plugin output is NULL!\n");
				continue;
			        }
			strncpy(plugin_output,temp_ptr,sizeof(plugin_output)-1);
			plugin_output[sizeof(plugin_output)-1]='\x0';
		

			total_packets++;

			/* clear the packet buffer */
			bzero(&send_packet,sizeof(send_packet));

			/* fill the packet with semi-random data */
			randomize_buffer((char *)&send_packet,sizeof(send_packet));

			/* copy the data we want to send into the packet */
			send_packet.packet_version=htonl(NSCA_PACKET_VERSION_1);
			strcpy(&send_packet.host_name[0],host_name);
			strcpy(&send_packet.svc_description[0],svc_description);
			send_packet.return_code=htonl(return_code);
			strcpy(&send_packet.plugin_output[0],plugin_output);

			/* calculate the crc 32 value of the packet */
			send_packet.crc32_value=0L;
			calculated_crc32=calculate_crc32((char *)&send_packet,sizeof(send_packet));
			send_packet.crc32_value=htonl(calculated_crc32);

			/* encrypt the packet */
			encrypt_buffer((char *)&send_packet,sizeof(send_packet),password,encryption_method);

			/* send the packet */
			rc=send(sd,(void *)&send_packet,sizeof(send_packet),0);

			/* there was an error sending the packet */
			if(rc==-1){
				printf("Error: Could not send data to host\n");
				close(sd);
				return STATE_UNKNOWN;
		                }

			/* for some reason we didn't send all the bytes we were supposed to */
			else if(rc<sizeof(send_packet)){
				printf("Warning: Sent only %d of %d bytes to host\n",rc,sizeof(send_packet));
				close(sd);
				return STATE_UNKNOWN;
			        }
		        }

		result=STATE_OK;

		/* close the connection */
		close(sd);

		printf("%d data packet(s) sent to host successfully.\n",total_packets);
	        }

	/* we couldn't connect */
	else
		printf("Error: Could not connect to host %s on port %d\n",server_name,server_port);

	/* reset the alarm */
	alarm(0);

	/* encryption/decryption routine cleanup */
	encrypt_cleanup(encryption_method);

	return result;
        }



/* process command line arguments */
int process_arguments(int argc, char **argv){
	int x;

	/* no options were supplied */
	if(argc<2)
		return ERROR;

	/* first option is always the server name/address */
	strncpy(server_name,argv[1],sizeof(server_name)-1);
	server_name[sizeof(server_name)-1]='\x0';

	/* process all remaining arguments */
	for(x=3;x<=argc;x++){

		/* port to connect to */
		if(!strcmp(argv[x-1],"-p")){
			if(x<argc){
				server_port=atoi(argv[x]);
				x++;
			        }
			else
				return ERROR;
		        }

		/* timeout when connecting */
		else if(!strcmp(argv[x-1],"-to")){
			if(x<argc){
				socket_timeout=atoi(argv[x]);
				if(socket_timeout<=0)
					return ERROR;
				x++;
			        }
			else
				return ERROR;
		        }

		/* config file */
		else if(!strcmp(argv[x-1],"-c")){
			if(x<argc){
				snprintf(config_file,sizeof(config_file)-1,argv[x]);
				config_file[sizeof(config_file)-1]='\x0';
				x++;
			        }
			else
				return ERROR;
		        }

		/* delimiter to use when parsing input */
		else if(!strcmp(argv[x-1],"-d")){
			if(x<argc){
				snprintf(delimiter,sizeof(delimiter)-1,argv[x]);
				delimiter[sizeof(delimiter)-1]='\x0';
				x++;
			        }
			else
				return ERROR;
		        }

		else
			return ERROR;
	        }

	return OK;
        }



void alarm_handler(int sig){

	printf("Error: Timeout after %d seconds\n",socket_timeout);

	exit(STATE_CRITICAL);
        }



/* read in the configuration file */
int read_config_file(char *filename){
	FILE *fp;
	char input_buffer[MAX_INPUT_BUFFER];
	char *temp_buffer;
	char *varname;
	char *varvalue;
	int line;


	/* open the config file for reading */
	fp=fopen(filename,"r");

	/* exit if we couldn't open the config file */
	if(fp==NULL){
		printf("Could not open config file '%s' for reading.\n",filename);
		return ERROR;
	        }	

	line=0;
	while(fgets(input_buffer,MAX_INPUT_BUFFER-1,fp)){

		line++;

		/* skip comments and blank lines */
		if(input_buffer[0]=='#')
			continue;
		if(input_buffer[0]=='\x0')
			continue;
		if(input_buffer[0]=='\n')
			continue;

		/* get the variable name */
		varname=strtok(input_buffer,"=");
		if(varname==NULL){

			printf("No variable name specified in config file '%s' - Line %d\n",filename,line);

			return ERROR;
		        }

		/* get the variable value */
		varvalue=strtok(NULL,"\n");
		if(varvalue==NULL){

			printf("No variable value specified in config file '%s' - Line %d\n",filename,line);

			return ERROR;
		        }

		if(strstr(input_buffer,"password")){
			if(strlen(varvalue)>sizeof(password)-1){

				printf("Password is too long in config file '%s' - Line %d\n",filename,line);

				return ERROR;
			        }
			strncpy(password,varvalue,sizeof(password)-1);
			password[sizeof(password)-1]='\x0';
		        }

		else if(strstr(input_buffer,"encryption_method")){

			encryption_method=atoi(varvalue);

			switch(encryption_method){
			case ENCRYPT_NONE:
				break;
			case ENCRYPT_XOR:
				break;

#ifdef HAVE_LIBMCRYPT
			case ENCRYPT_DES:
				break;
			case ENCRYPT_3DES:
				break;
			case ENCRYPT_CAST128:
				break;
			case ENCRYPT_CAST256:
				break;
			case ENCRYPT_XTEA:
				break;
			case ENCRYPT_3WAY:
				break;
			case ENCRYPT_BLOWFISH:
				break;
			case ENCRYPT_TWOFISH:
				break;
			case ENCRYPT_LOKI97:
				break;
			case ENCRYPT_RC2:
				break;
			case ENCRYPT_ARCFOUR:
				break;
			case ENCRYPT_RIJNDAEL128:
				break;
			case ENCRYPT_RIJNDAEL192:
				break;
			case ENCRYPT_RIJNDAEL256:
				break;
			case ENCRYPT_WAKE:
				break;
			case ENCRYPT_SERPENT:
				break;
			case ENCRYPT_ENIGMA:
				break;
			case ENCRYPT_GOST:
				break;
			case ENCRYPT_SAFER64:
				break;
			case ENCRYPT_SAFER128:
				break;
			case ENCRYPT_SAFERPLUS:
				break;
#endif
			default:
				printf("Invalid encryption method (%d) in config file '%s' - Line %d\n",encryption_method,filename,line);
#ifndef HAVE_LIBMCRYPT
				if(encryption_method>=2)
					printf("Client was not compiled with mcrypt library, so encryption is unavailable.\n");
#endif
				return ERROR;
			        }
		        }

		else{
			printf("Unknown option specified in config file '%s' - Line %d\n",filename,line);

			return ERROR;
		        }

	        }


	/* close the config file */
	fclose(fp);

	return OK;
	}

