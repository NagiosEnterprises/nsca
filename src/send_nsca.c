/**********************************************************************************
 *
 * SEND_NSCA.C - NSCA Client
 * License: GPL v2
 * Copyright (c) 2000-2007 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 01-27-2012
 *
 * Command line: SEND_NSCA <host_address> [-p port] [-to to_sec] [-c config_file]
 *
 * Description:
 *
 *
 *********************************************************************************/

/*#define DEBUG*/

#include "../include/common.h"
#include "../include/config.h"
#include "../include/netutils.h"
#include "../include/utils.h"

time_t start_time,end_time;

int server_port=DEFAULT_SERVER_PORT;
char server_name[MAX_HOST_ADDRESS_LENGTH];
char password[MAX_INPUT_BUFFER]="";
char config_file[MAX_INPUT_BUFFER]="send_nsca.cfg";
char delimiter[2]="\t";
char block_delimiter[2]=BLOCK_DELIMITER;

char received_iv[TRANSMITTED_IV_SIZE];

int socket_timeout=DEFAULT_SOCKET_TIMEOUT;

int warning_time=0;
int check_warning_time=FALSE;
int critical_time=0;
int check_critical_time=FALSE;
int encryption_method=ENCRYPT_XOR;
time_t packet_timestamp;
struct crypt_instance *CI=NULL;

int show_help=FALSE;
int show_license=FALSE;
int show_version=FALSE;


int process_arguments(int,char **);
int read_config_file(char *);
int read_init_packet(int);
void alarm_handler(int);
void clear_password(void);
static void do_exit(int);




int main(int argc, char **argv){
	int sd;
	int rc;
	int result;
	data_packet send_packet;
	int bytes_to_send;
	char input[MAX_INPUT_BUFFER];
	char input_buffer[MAX_INPUT_BUFFER];
	char *temp_ptr;
	char host_name[MAX_HOSTNAME_LENGTH];
	char svc_description[MAX_DESCRIPTION_LENGTH];
	char plugin_output[MAX_PLUGINOUTPUT_LENGTH];
	int total_packets=0;
	int16_t return_code;
	u_int32_t calculated_crc32;
	char *inputptr, *ptr1, *ptr2, *ptr3, *ptr4;


	/* process command-line arguments */
	result=process_arguments(argc,argv);

	if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE){

		if(result!=OK)
			printf("Incorrect command line arguments supplied\n");
		printf("\n");
		printf("NSCA Client %s\n",PROGRAM_VERSION);
		printf("Copyright (c) 2000-2007 Ethan Galstad (www.nagios.org)\n");
		printf("Last Modified: %s\n",MODIFICATION_DATE);
		printf("License: GPL v2\n");
		printf("Encryption Routines: ");
#ifdef HAVE_LIBMCRYPT
		printf("AVAILABLE");
#else
		printf("NOT AVAILABLE");
#endif		
		printf("\n");
		printf("\n");
	        }

	if(result!=OK || show_help==TRUE){
		printf("Usage: %s -H <host_address> [-p port] [-to to_sec] [-d delim] [-c config_file]\n",argv[0]);
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
		printf("This utility is used to send passive check results to the NSCA daemon.  Host and\n");
		printf("Service check data that is to be sent to the NSCA daemon is read from standard\n");
		printf("input. Input should be provided in the following format (tab-delimited unless\n");
		printf("overriden with -d command line argument, one entry per line):\n");
		printf("\n");
		printf("Service Checks:\n");
		printf("<host_name>[tab]<svc_description>[tab]<return_code>[tab]<plugin_output>[newline]\n\n");
		printf("Host Checks:\n");
		printf("<host_name>[tab]<return_code>[tab]<plugin_output>[newline]\n\n");
		printf("When submitting multiple simultaneous results, separate each set with the ETB\n");
                printf("character (^W or 0x17)\n");
	        }

	if(show_license==TRUE)
		display_license();

        if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE)
		do_exit(STATE_UNKNOWN);



	/* read the config file */
	result=read_config_file(config_file);	

	/* exit if there are errors... */
	if(result==ERROR){
		printf("Error: Config file '%s' contained errors...\n",config_file);
		do_exit(STATE_CRITICAL);
		}

	/* generate the CRC 32 table */
	generate_crc32_table();

	/* initialize alarm signal handling */
	signal(SIGALRM,alarm_handler);

	/* set socket timeout */
	alarm(socket_timeout);

	time(&start_time);

	/* try to connect to the host at the given port number */
	result=my_tcp_connect(server_name,server_port,&sd);

	/* we couldn't connect */
	if(result!=STATE_OK){
		printf("Error: Could not connect to host %s on port %d\n",server_name,server_port);
		do_exit(STATE_CRITICAL);
	        }

#ifdef DEBUG
	printf("Connected okay...\n");
#endif

	/* read the initialization packet containing the IV and timestamp */
	result=read_init_packet(sd);
	if(result!=OK){
		printf("Error: Could not read init packet from server\n");
		close(sd);
		do_exit(STATE_CRITICAL);
	        }

#ifdef DEBUG
	printf("Got init packet from server\n");
#endif

	/* initialize encryption/decryption routines with the IV we received from the server */
        if(encrypt_init(password,encryption_method,received_iv,&CI)!=OK){
		printf("Error: Failed to initialize encryption libraries for method %d\n",encryption_method);
		close(sd);
		do_exit(STATE_CRITICAL);
	        }

#ifdef DEBUG
	printf("Initialized encryption routines\n");
#endif


	/**** WE'RE CONNECTED AND READY TO SEND ****/

	/* read all data from STDIN until there isn't anymore */

	while(!feof(stdin)){
		int c = getc(stdin);
		if (c == -1){
			break;
			}
		int pos = 0;
		while (c != 23){
			if (c == -1){	// in case we don't terminate properly
					// or are in single-input mode.
				break;
				}
			input_buffer[pos] = c;
			c = getc(stdin);
			pos++;
			}
		input_buffer[pos] = 0;
		strip(input_buffer);

		if(!strcmp(input_buffer,""))
			continue;

		/* get the host name */
		ptr1=strtok(input_buffer,delimiter);
		if(ptr1==NULL)
			continue;

		/* get the service description or return code */
		ptr2=strtok(NULL,delimiter);
		if(ptr2==NULL)
			continue;

		/* get the return code or plugin output */
		ptr3=strtok(NULL,delimiter);
		if(ptr3==NULL)
			continue;

		/* get the plugin output - if NULL, this is a host check result */
		ptr4=strtok(NULL,"\x0");
		
		strncpy(host_name,ptr1,sizeof(host_name)-1);
		host_name[sizeof(host_name)-1]='\x0';
		if(ptr4==NULL){
			strcpy(svc_description,"");
			return_code=atoi(ptr2);
                        ptr3=escape_newlines(ptr3);
			strncpy(plugin_output,ptr3,sizeof(plugin_output)-1);
		        }
		else{
			strncpy(svc_description,ptr2,sizeof(svc_description)-1);
			return_code=atoi(ptr3);
                        ptr4=escape_newlines(ptr4);
			strncpy(plugin_output,ptr4,sizeof(plugin_output)-1);
		        }

		svc_description[sizeof(svc_description)-1]='\x0';
		plugin_output[sizeof(plugin_output)-1]='\x0';

		/* increment count of packets we're sending */
		total_packets++;

		/* clear the packet buffer */
		bzero(&send_packet,sizeof(send_packet));

		/* fill the packet with semi-random data */
		randomize_buffer((char *)&send_packet,sizeof(send_packet));

		/* copy the data we want to send into the packet */
		send_packet.packet_version=(int16_t)htons(NSCA_PACKET_VERSION_3);
		send_packet.return_code=(int16_t)htons(return_code);
		strcpy(&send_packet.host_name[0],host_name);
		strcpy(&send_packet.svc_description[0],svc_description);
		strcpy(&send_packet.plugin_output[0],plugin_output);

		/* use timestamp provided by the server */
		send_packet.timestamp=(u_int32_t)htonl(packet_timestamp);

		/* calculate the crc 32 value of the packet */
		send_packet.crc32_value=(u_int32_t)0L;
		calculated_crc32=calculate_crc32((char *)&send_packet,sizeof(send_packet));
		send_packet.crc32_value=(u_int32_t)htonl(calculated_crc32);

		/* encrypt the packet */
		encrypt_buffer((char *)&send_packet,sizeof(send_packet),password,encryption_method,CI);

		/* send the packet */
		bytes_to_send=sizeof(send_packet);
		rc=sendall(sd,(char *)&send_packet,&bytes_to_send);

		/* there was an error sending the packet */
		if(rc==-1){
			printf("Error: Could not send data to host\n");
			close(sd);
			do_exit(STATE_UNKNOWN);
	                }

		/* for some reason we didn't send all the bytes we were supposed to */
		else if(bytes_to_send<sizeof(send_packet)){
			printf("Warning: Sent only %d of %d bytes to host\n",rc,sizeof(send_packet));
			close(sd);
			return STATE_UNKNOWN;
		        }
	        }

#ifdef DEBUG
	printf("Done sending data\n");
#endif

	/* close the connection */
	close(sd);

	printf("%d data packet(s) sent to host successfully.\n",total_packets);

	/* exit cleanly */
	do_exit(STATE_OK);

	/* no compiler complaints here... */
	return STATE_OK;
        }



/* exit */
static void do_exit(int return_code){

	/* reset the alarm */
	alarm(0);

	/* encryption/decryption routine cleanup */
	encrypt_cleanup(encryption_method,CI);

#ifdef DEBUG
	printf("Cleaned up encryption routines\n");
#endif

	/*** CLEAR SENSITIVE INFO FROM MEMORY ***/

        /* overwrite password */
        clear_buffer(password,sizeof(password));

	/* disguise decryption method */
	encryption_method=-1;

        exit(return_code);
        }



/* reads initialization packet (containing IV and timestamp) from server */
int read_init_packet(int sock){
        int rc;
        init_packet receive_packet;
        int bytes_to_recv;

        /* clear the IV and timestamp */
        bzero(&received_iv,TRANSMITTED_IV_SIZE);
        packet_timestamp=(time_t)0;

        /* get the init packet from the server */
        bytes_to_recv=sizeof(receive_packet);
        rc=recvall(sock,(char *)&receive_packet,&bytes_to_recv,socket_timeout);

        /* recv() error or server disconnect */
        if(rc<=0){
                printf("Error: Server closed connection before init packet was received\n");
                return ERROR;
                }

        /* we couldn't read the correct amount of data, so bail out */
        else if(bytes_to_recv!=sizeof(receive_packet)){
                printf("Error: Init packet from server was too short (%d bytes received, %d expected)\n",bytes_to_recv,sizeof(receive_packet));
                return ERROR;
                }

        /* transfer the IV and timestamp */
        memcpy(&received_iv,&receive_packet.iv[0],TRANSMITTED_IV_SIZE);
        packet_timestamp=(time_t)ntohl(receive_packet.timestamp);

        return OK;
        }



/* process command line arguments */
int process_arguments(int argc, char **argv){
	int x;

	/* no options were supplied */
	if(argc<2){
		show_help=TRUE;
		return OK;
	        }

	/* support old command-line syntax (host name first argument) */
	strncpy(server_name,argv[1],sizeof(server_name)-1);
	server_name[sizeof(server_name)-1]='\x0';

	/* process arguments (host name is usually 1st argument) */
	for(x=2;x<=argc;x++){

		/* show usage */
		if(!strcmp(argv[x-1],"-h") || !strcmp(argv[x-1],"--help"))
			show_help=TRUE;

		/* show license */
		else if(!strcmp(argv[x-1],"-l") || !strcmp(argv[x-1],"--license"))
			show_license=TRUE;

		/* show version */
		else if(!strcmp(argv[x-1],"-V") || !strcmp(argv[x-1],"--version"))
			show_version=TRUE;

		/* server name/address */
		else if(!strcmp(argv[x-1],"-H")){
			if(x<argc){
				strncpy(server_name,argv[x],sizeof(server_name));
				server_name[sizeof(server_name)-1]='\x0';
				x++;
			        }
			else
				return ERROR;
		        }

		/* port to connect to */
		else if(!strcmp(argv[x-1],"-p")){
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
				snprintf(config_file,sizeof(config_file),"%s",argv[x]);
				config_file[sizeof(config_file)-1]='\x0';
				x++;
			        }
			else
				return ERROR;
		        }

		/* delimiter to use when parsing input */
		else if(!strcmp(argv[x-1],"-d")){
			if(x<argc){
				snprintf(delimiter,sizeof(delimiter),"%s",argv[x]);
				delimiter[sizeof(delimiter)-1]='\x0';
				x++;
			        }
			else
				return ERROR;
		        }

		else if(x>2)
			return ERROR;
	        }

	return OK;
        }



/* handle timeouts */
void alarm_handler(int sig){

	printf("Error: Timeout after %d seconds\n",socket_timeout);

	do_exit(STATE_CRITICAL);
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
			strncpy(password,varvalue,sizeof(password));
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

