/*******************************************************************************
 *
 * NSCA.C - Nagios Service Check Acceptor
 * Copyright (c) 2000-2001 Ethan Galstad (nagios@nagios.org)
 * Version: 1.2
 * License: GPL
 *
 * Last Modified: 06-23-2001
 *
 * Command line: NSCA <config_file>
 *
 * Description:
 *
 * This program is designed to run as a daemon on the main Nagios machine 
 * and accept service check results from remote hosts.
 * 
 ******************************************************************************/

#include "../common/common.h"
#include "../common/config.h"
#include "netutils.h"
#include "utils.h"


#define PROGRAM_VERSION "1.2"
#define MODIFICATION_DATE "06-23-2001"

char allowed_hosts[MAX_INPUT_BUFFER];
int server_port=DEFAULT_SERVER_PORT;
char server_address[16]="0.0.0.0";
int socket_timeout=DEFAULT_SOCKET_TIMEOUT;

char command_file[MAX_INPUT_BUFFER]="";
char password[MAX_INPUT_BUFFER]="";

void wait_for_connections(void);
void handle_connection(int);
int read_config_file(char *);
void sighandler(int);
int is_an_allowed_host(char *);
int open_command_file(void);
void close_command_file(void);
int write_service_check_result(char *,char *,int,char *,time_t);

int use_inetd=TRUE;
int debug=FALSE;
int aggregate_writes=FALSE;
int decryption_method=ENCRYPT_XOR;

FILE *command_file_fp=NULL;



int main(int argc, char **argv){
	int error=FALSE;
	int result;
	char config_file[MAX_INPUT_BUFFER];
	char buffer[MAX_INPUT_BUFFER];

	/* check command line arguments */
	if(argc!=3)
		error=TRUE;
	else{
		if(!strcmp(argv[1],"-d"))
			use_inetd=FALSE;
		else if(!strcmp(argv[1],"-i"))
			use_inetd=TRUE;
		else
			error=TRUE;
	        }

	if(error==TRUE){

		printf("\n");
		printf("NSCA - Nagios Service Check Acceptor\n");
		printf("Copyright (c) 2000-2001 Ethan Galstad (nagios@nagios.org)\n");
		printf("Version: %s\n",PROGRAM_VERSION);
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
		printf("Usage: %s <-i | -d> <config_file>\n",argv[0]);
		printf("\n");
		printf("Options:\n");
		printf("  -i      Run as a service under inetd\n");
		printf("  -d      Run as a standalone daemon without inetd\n");
		printf("\n");
		printf("Notes:\n");
		printf("This program is designed to accept passive service check results from\n");
		printf("remote hosts that use the send_nsca utility.  Can run as a service\n");
		printf("under inetd (read the docs for info on this), or as a standalone\n");
		printf("daemon if you wish.\n");
		printf("\n");

		exit(STATE_UNKNOWN);
		}

	/* open a connection to the syslog facility */
        openlog("nsca",LOG_PID,LOG_DAEMON); 

	/* grab the config file */
	strncpy(config_file,argv[2],sizeof(config_file)-1);
	config_file[sizeof(config_file)-1]='\x0';

	/* make sure the config file uses an absolute path */
	if(config_file[0]!='/'){

		/* save the name of the config file */
		strncpy(buffer,config_file,sizeof(buffer));
		buffer[sizeof(buffer)-1]='\x0';

		/* get absolute path of current working directory */
		strcpy(config_file,"");
		getcwd(config_file,sizeof(config_file));

		/* append a forward slash */
		strncat(config_file,"/",sizeof(config_file)-2);
		config_file[sizeof(config_file)-1]='\x0';

		/* append the config file to the path */
		strncat(config_file,buffer,sizeof(config_file)-strlen(config_file)-1);
		config_file[sizeof(config_file)-1]='\x0';
	        }

	/* read the config file */
	result=read_config_file(config_file);	

	/* exit if there are errors... */
	if(result==ERROR){
		syslog(LOG_ERR,"Config file '%s' contained errors, bailing out...",config_file);
		return STATE_CRITICAL;
		}

	/* generate the CRC 32 table */
	generate_crc32_table();

	/* initialize encryption/decryption routines */
	if(encrypt_init(password,decryption_method)!=OK)
		return STATE_CRITICAL;

	/* if we're running under inetd... */
	if(use_inetd==TRUE)
		handle_connection(0);

	/* else daemonize and start listening for requests... */
	else if(fork()==0){

		/* wait for connections */
		wait_for_connections();
	        }

	/* encryption/decryption routine cleanup */
	encrypt_cleanup(decryption_method);

	/* We are now running in daemon mode, or the connection handed over by inetd has
	   been completed, so the parent process exits */
        return STATE_OK;
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
	if(fp==NULL)
		return ERROR;

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
			syslog(LOG_ERR,"No variable name specified in config file '%s' - Line %d\n",filename,line);
			return ERROR;
		        }

		/* get the variable value */
		varvalue=strtok(NULL,"\n");
		if(varvalue==NULL){
			syslog(LOG_ERR,"No variable value specified in config file '%s' - Line %d\n",filename,line);
			return ERROR;
		        }

		if(!strcmp(varname,"server_port")){
			server_port=atoi(varvalue);
			if(server_port<1024){
				syslog(LOG_ERR,"Invalid port number specified in config file '%s' - Line %d\n",filename,line);
				return ERROR;
			        }
		        }

                else if(!strcmp(varname,"server_address")){
                        strncpy(server_address,varvalue,sizeof(server_address) - 1);
                        server_address[sizeof(server_address) - 1] = '\0';
                        }

		else if(!strcmp(varname,"allowed_hosts")){
			if(strlen(varvalue)>sizeof(allowed_hosts)-1){
				syslog(LOG_ERR,"Allowed hosts list too long in config file '%s' - Line %d\n",filename,line);
				return ERROR;
			        }
			strncpy(allowed_hosts,varvalue,sizeof(allowed_hosts));
			allowed_hosts[sizeof(allowed_hosts)-1]='\x0';
		        }

		else if(strstr(input_buffer,"command_file")){
			if(strlen(varvalue)>sizeof(command_file)-1){
				syslog(LOG_ERR,"Command file name is too long in config file '%s' - Line %d\n",filename,line);
				return ERROR;
			        }
			strncpy(command_file,varvalue,sizeof(command_file)-1);
			command_file[sizeof(command_file)-1]='\x0';
		        }

		else if(strstr(input_buffer,"password")){
			if(strlen(varvalue)>sizeof(password)-1){
				syslog(LOG_ERR,"Password is too long in config file '%s' - Line %d\n",filename,line);
				return ERROR;
			        }
			strncpy(password,varvalue,sizeof(password)-1);
			password[sizeof(password)-1]='\x0';
		        }

		else if(strstr(input_buffer,"decryption_method")){

			decryption_method=atoi(varvalue);

			switch(decryption_method){
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
				syslog(LOG_ERR,"Invalid decryption method (%d) in config file '%s' - Line %d\n",decryption_method,filename,line);
#ifndef HAVE_LIBMCRYPT
				if(decryption_method>=2)
					syslog(LOG_ERR,"Daemon was not compiled with mcrypt library, so decryption is unavailable.\n");
#endif
				return ERROR;
			        }
		        }

		else if(strstr(input_buffer,"debug")){
			if(atoi(varvalue)>0)
				debug=TRUE;
			else 
				debug=FALSE;
		        }

		else if(strstr(input_buffer,"aggregate_writes")){
			if(atoi(varvalue)>0)
				aggregate_writes=TRUE;
			else 
				aggregate_writes=FALSE;
		        }

		else{
			syslog(LOG_ERR,"Unknown option specified in config file '%s' - Line %d\n",filename,line);

			return ERROR;
		        }

	        }


	/* close the config file */
	fclose(fp);

	return OK;
	}



/* wait for incoming connection requests */
void wait_for_connections(void){
	struct sockaddr_in myname;
	struct sockaddr_in *nptr;
	struct sockaddr addr;
	int rc;
	int sock, new_sd, addrlen;
	char connecting_host[16];
	pid_t pid;
	int flag=1;

	/* create a socket for listening */
	sock=socket(AF_INET,SOCK_STREAM,0);

	/* exit if we couldn't create the socket */
	if(sock<0){
	        syslog(LOG_ERR,"Network server socket failure (%d: %s)",errno,strerror(errno));
	        exit (STATE_CRITICAL);
		}

        /* set the reuse address flag so we don't get errors when restarting */
        flag=1;
        if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char *)&flag,sizeof(flag))<0){
		syslog(LOG_ERR,"Could not set reuse address option on socket!\n");
		exit(STATE_UNKNOWN);
	        }

	myname.sin_family=AF_INET;
	myname.sin_port=htons(server_port);
 	bzero(&myname.sin_zero,8);

	/* what address should we bind to? */
        if(!strlen(server_address))
		myname.sin_addr.s_addr=INADDR_ANY;

	else if(!my_inet_aton(server_address,&myname.sin_addr)){
		syslog(LOG_ERR,"Server address is not a valid IP address\n");
		exit (STATE_CRITICAL);
                }


	/* bind the address to the Internet socket */
	if(bind(sock,(struct sockaddr *)&myname,sizeof(myname))<0){
		syslog(LOG_ERR,"Network server bind failure (%d: %s)\n",errno,strerror(errno));
	        exit (STATE_CRITICAL);
	        }

	/* open the socket for listening */
	if(listen(sock,5)<0){
	    	syslog(LOG_ERR,"Network server listen failure (%d: %s)\n",errno,strerror(errno));
	        exit (STATE_CRITICAL);
		}

	/* log info to syslog facility */
        syslog(LOG_NOTICE,"Starting up daemon");

	if(debug==TRUE){
		syslog(LOG_DEBUG,"Listening for connections on port %d\n",htons(myname.sin_port));
		syslog(LOG_DEBUG,"Allowing connections from: %s\n",allowed_hosts);
	        }

	/* listen for connection requests - fork() if we get one */
	while(1){

		/* wait for a connection request */
	        while(1){
			new_sd=accept(sock,0,0);
			if(new_sd>=0 || (errno!=EWOULDBLOCK && errno!=EINTR))
				break;
			sleep(1);
		        }

		/* hey, there was an error... */
		if(new_sd<0){

			/* log error to syslog facility */
			syslog(LOG_ERR,"Network server accept failure (%d: %s)",errno,strerror(errno));

			/* close socket prior to exiting */
			close(sock);

			return;
			}

		/* child process should handle the connection */
		pid=fork();
    		if(pid==0){

			/* fork again so we don't create zombies */
			pid=fork();
			if(pid==0){

				/* child does not need to listen for connections, so close the socket */
				close(sock);  

				/* find out who just connected... */
				addrlen=sizeof(addr);
				rc=getpeername(new_sd,&addr,&addrlen);

				if(rc<0){

				        /* log error to syslog facility */
					syslog(LOG_ERR,"Error: Network server getpeername() failure (%d: %s)",errno,strerror(errno));

				        /* close socket prior to exiting */
					close(new_sd);

					return;
		                        }

				nptr=(struct sockaddr_in *)&addr;

				/* log info to syslog facility */
				if(debug==TRUE)
					syslog(LOG_DEBUG,"Connection from %s port %d",inet_ntoa(nptr->sin_addr),nptr->sin_port);

				/* is this is blessed machine? */
				snprintf(connecting_host,sizeof(connecting_host),"%s",inet_ntoa(nptr->sin_addr));
				connecting_host[sizeof(connecting_host)-1]='\x0';

				if(!is_an_allowed_host(connecting_host)){

				        /* log error to syslog facility */
					syslog(LOG_ERR,"Host %s is not allowed to talk to us!", inet_ntoa(nptr->sin_addr));
			                }
				else{

				        /* log info to syslog facility */
					if(debug==TRUE)
						syslog(LOG_DEBUG,"Host address checks out ok");

				        /* handle the client connection */
					handle_connection(new_sd);
			                }

				/* log info to syslog facility */
				if(debug==TRUE)
					syslog(LOG_DEBUG,"Connection from %s closed.",inet_ntoa(nptr->sin_addr));

				/* close socket prior to exiting */
				close (new_sd);

				return;
    			        }

			/* parent returns immediately */
			else
				exit(STATE_OK);
		        }
		
		/* parent waits for first child to return, so no zombies are created */
		else{
			/* parent doesn't need the new connection */
			close(new_sd);
			
			/* wait for the first child to return */
			waitpid(pid,NULL,0);
		        }
  		}

	/* we shouldn't ever get here... */
	syslog(LOG_NOTICE,"Terminating");

	return;
	}



/* handles a client connection */
void handle_connection(int sock){
	packet receive_packet;
	char buffer[MAX_INPUT_BUFFER];
	int result=STATE_OK;
	int rc;
	char host_name[MAX_HOSTNAME_LENGTH];
	char svc_description[MAX_DESCRIPTION_LENGTH];
	int return_code;
	char plugin_output[MAX_PLUGINOUTPUT_LENGTH];
	time_t start_time;
	time_t current_time;
	unsigned long calculated_crc32;
	unsigned long packet_crc32;

	/* log info to syslog facility */
	if(debug==TRUE)
		syslog(LOG_DEBUG,"Handling the connection...");

	/* socket should be non-blocking */
	fcntl(sock,F_SETFL,O_NONBLOCK);

	time(&start_time);

	/* open the command file if we're aggregating writes */
	if(aggregate_writes==TRUE){
		if(open_command_file()==ERROR)
			return;
	        }

	/* process all data we get from the client... */
	while(1){

		/* clear the receive packet buffer */
		bzero(&receive_packet,sizeof(receive_packet));

		/* read the packet */
		rc=recv(sock,(void *)&receive_packet,sizeof(receive_packet),0);

		/* we haven't received data, hang around for a bit more */
		if(rc==-1 && errno==EAGAIN){
			time(&current_time);
			if(current_time-start_time>DEFAULT_SOCKET_TIMEOUT){
				break;
			        }
			sleep(1);
			continue;
		        }

		/* the client connection was closed */
		else if(rc==0)
		        break;

		/* there was an error receiving data... */
		else if(rc==-1){
			syslog(LOG_ERR,"Could not read request from client, ignoring packet...");
			break;
	                }

		/* we couldn't read the correct amount of data, so bail out */
		else if(rc!=sizeof(receive_packet)){
			syslog(LOG_ERR,"Data sent from client was too short (%d < %d), ignoring packet...",rc,sizeof(receive_packet));
			break;
		        }

		/* decrypt the packet */
		decrypt_buffer((char *)&receive_packet,sizeof(receive_packet),password,decryption_method);

		/* make sure this is the right type of packet */
		if(ntohl(receive_packet.packet_version)!=NSCA_PACKET_VERSION_1){
			syslog(LOG_ERR,"Received invalid packet type/version from client - possibly due to client using wrong password or crypto algorithm?");
			break;
	                }

		/* check the crc 32 value */
		packet_crc32=ntohl(receive_packet.crc32_value);
		receive_packet.crc32_value=0L;
		calculated_crc32=calculate_crc32((char *)&receive_packet,sizeof(receive_packet));
		if(packet_crc32!=calculated_crc32){
			syslog(LOG_ERR,"Dropping packet with invalid CRC32 - possibly due to client using wrong password or crypto algorithm?");
			break;
		        }

		/* get the service check info */
		strncpy(host_name,receive_packet.host_name,sizeof(host_name)-1);
		host_name[sizeof(host_name)-1]='\x0';
		strncpy(svc_description,receive_packet.svc_description,sizeof(svc_description)-1);
		svc_description[sizeof(svc_description)-1]='\x0';
		return_code=ntohl(receive_packet.return_code);
		strncpy(plugin_output,receive_packet.plugin_output,sizeof(plugin_output)-1);
		plugin_output[sizeof(plugin_output)-1]='\x0';

		/* log info to syslog facility */
		if(debug==TRUE)
			syslog(LOG_NOTICE,"Host Name: '%s', Service Description: '%s', Return Code: '%d', Output: '%s'",host_name,svc_description,return_code,plugin_output);

		/* write the check result to the Nagios command file */
		write_service_check_result(host_name,svc_description,return_code,plugin_output,time(NULL));
	        }

	/* close the command file if we're aggregating writes */
	if(aggregate_writes==TRUE)
		close_command_file();

	return;
        }


/* checks to see if a given host is allowed to talk to us */
int is_an_allowed_host(char *connecting_host){
	char temp_buffer[MAX_INPUT_BUFFER];
	char *temp_ptr;

	strncpy(temp_buffer,allowed_hosts,sizeof(temp_buffer));
	temp_buffer[sizeof(temp_buffer)-1]='\x0';

	for(temp_ptr=strtok(temp_buffer,",");temp_ptr!=NULL;temp_ptr=strtok(NULL,",")){
		if(!strcmp(connecting_host,temp_ptr))
			return 1;
	        }

	return 0;
        }


/* writes service check results to the Nagios command file */
int write_service_check_result(char *host_name, char *svc_description, int return_code, char *plugin_output, time_t check_time){

	if(aggregate_writes==FALSE){
		if(open_command_file()==ERROR)
			return ERROR;
	        }

	fprintf(command_file_fp,"[%lu] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%d;%s\n",(unsigned long)check_time,host_name,svc_description,return_code,plugin_output);

	if(aggregate_writes==FALSE)
		close_command_file();
	
	return OK;
        }


/* opens the command file for appending */
int open_command_file(void){

	/* open the command file for appending */
	command_file_fp=fopen(command_file,"a");
	if(command_file_fp==NULL){

		if(debug==TRUE)
			syslog(LOG_ERR,"Could not open command file '%s' for appending",command_file);

		return ERROR;
	        }

	return OK;
        }


/* closes the command file */
void close_command_file(void){

	fclose(command_file_fp);

	return;
        }


