/*******************************************************************************
 *
 * NSCA.C - Nagios Service Check Acceptor
 * Copyright (c) 2000-2002 Ethan Galstad (nagios@nagios.org)
 * License: GPL
 *
 * Last Modified: 10-09-2002
 *
 * Command line: NSCA -c <config_file> [mode]
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


static char allowed_hosts[MAX_INPUT_BUFFER];
static int server_port=DEFAULT_SERVER_PORT;
static char server_address[16]="0.0.0.0";
static int socket_timeout=DEFAULT_SOCKET_TIMEOUT;

static char config_file[MAX_INPUT_BUFFER]="nsca.cfg";
static char alternate_dump_file[MAX_INPUT_BUFFER]="/dev/null";
static char command_file[MAX_INPUT_BUFFER]="";
static char password[MAX_INPUT_BUFFER]="";

static void handle_events(void);
static void wait_for_connections(void);
static void handle_connection(int,void *);
static void accept_connection(int,void *);
static void handle_connection_read(int,void *);
static int process_arguments(int,char **);
static int read_config_file(char *);
static int is_an_allowed_host(char *);
static int open_command_file(void);
static void close_command_file(void);
static void install_child_handler(void);
static int drop_privileges(char *,char *);
static int write_check_result(char *,char *,int,char *,time_t);
static void do_exit(int);

static enum { OPTIONS_ERROR, SINGLE_PROCESS_DAEMON, MULTI_PROCESS_DAEMON, INETD } mode=SINGLE_PROCESS_DAEMON;
static int debug=FALSE;
static int aggregate_writes=FALSE;
static int decryption_method=ENCRYPT_XOR;
static int append_to_file=FALSE;
static unsigned long max_packet_age=30;

char *nsca_user=NULL;
char *nsca_group=NULL;

int show_help=FALSE;
int show_license=FALSE;
int show_version=FALSE;

static FILE *command_file_fp=NULL;

struct handler_entry{
	void (*handler)(int, void *);
	void *data;
	int fd;
        };

struct handler_entry *rhand=NULL;
struct handler_entry *whand=NULL;
struct pollfd *pfds=NULL;
int maxrhand=0;
int maxwhand=0;
int maxpfds=0;
int nrhand=0;
int nwhand=0;
int npfds=0;



int main(int argc, char **argv){
        char buffer[MAX_INPUT_BUFFER];
        int result;


	/* process command-line arguments */
	result=process_arguments(argc,argv);

        if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE){

		if(result!=OK)
			printf("Incorrect command line arguments supplied\n");
                printf("\n");
                printf("NSCA - Nagios Service Check Acceptor\n");
                printf("Copyright (c) 2000-2002 Ethan Galstad (nagios@nagios.org)\n");
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
	        }

	if(result!=OK || show_help==TRUE){
                printf("Usage: %s -c <config_file> [mode]\n",argv[0]);
                printf("\n");
                printf("Options:\n");
		printf(" <config_file> = Name of config file to use\n");
		printf(" [mode]        = Determines how NSCA should run. Valid modes:\n");
                printf("   --inetd     = Run as a service under inetd or xinetd\n");
                printf("   --daemon    = Run as a standalone multi-process daemon\n");
                printf("   --single    = Run as a standalone single-process daemon (default)\n");
                printf("\n");
                printf("Notes:\n");
                printf("This program is designed to accept passive service check results from\n");
                printf("remote hosts that use the send_nsca utility.  Can run as a service\n");
                printf("under inetd or xinetd (read the docs for info on this), or as a\n");
                printf("standalone daemon.\n");
                printf("\n");
                }

	if(show_license==TRUE)
		display_license();

        if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE)
		do_exit(STATE_UNKNOWN);


        /* open a connection to the syslog facility */
        openlog("nsca",LOG_PID,LOG_DAEMON); 

	/* make sure the config file uses an absolute path */
	if(config_file[0]!='/'){

		/* save the name of the config file */
		strncpy(buffer,config_file,sizeof(buffer));
		buffer[sizeof(buffer)-1]='\0';

		/* get absolute path of current working directory */
		strcpy(config_file,"");
		getcwd(config_file,sizeof(config_file));

		/* append a forward slash */
		strncat(config_file,"/",sizeof(config_file)-2);
		config_file[sizeof(config_file)-1]='\0';

		/* append the config file to the path */
		strncat(config_file,buffer,sizeof(config_file)-strlen(config_file)-1);
		config_file[sizeof(config_file)-1]='\0';
	        }

	/* read the config file */
        result=read_config_file(config_file);   

        /* exit if there are errors... */
        if(result==ERROR)
                do_exit(STATE_CRITICAL);

        /* generate the CRC 32 table */
        generate_crc32_table();


	/* how should we handle client connections? */
        switch(mode){

        case INETD:
                /* if we're running under inetd, handle one connection and get out */
                handle_connection(0,NULL);
                break;

        case MULTI_PROCESS_DAEMON:
		/* older style, mult-process daemon */
		/* execution cascades below... */
                install_child_handler();

        case SINGLE_PROCESS_DAEMON:
                /* daemonize and start listening for requests... */
                if(fork()==0){

                        /* we're a daemon - set up a new process group */
                        setsid();

			/* close standard file descriptors */
                        close(0);
                        close(1);
                        close(2);

			/* redirect standard descriptors to /dev/null */
			open("/dev/null",O_RDONLY);
			open("/dev/null",O_WRONLY);
			open("/dev/null",O_WRONLY);

			/* drop privileges */
			drop_privileges(nsca_user,nsca_group);

                        /* wait for connections */
                        wait_for_connections();
                        }
                break;

        default:
                break;
                }

        /* We are now running in daemon mode, or the connection handed over by inetd has
           been completed, so the parent process exits */
        do_exit(STATE_OK);

	/* keep the compilers happy... */
	return STATE_OK;
        }



/* exit cleanly */
static void do_exit(int return_code){

        /* close the command file if its still open */
        if (command_file_fp!=NULL)
                close_command_file();

	/*** CLEAR SENSITIVE INFO FROM MEMORY ***/

        /* overwrite password */
        clear_buffer(password,sizeof(password));

	/* disguise decryption method */
	decryption_method=-1;

        exit(return_code);
        }



/* read in the configuration file */
static int read_config_file(char *filename){
        FILE *fp;
        char input_buffer[MAX_INPUT_BUFFER];
        char *varname;
        char *varvalue;
        int line;

        /* open the config file for reading */
        fp=fopen(filename,"r");

        /* exit if we couldn't open the config file */
        if(fp==NULL){
		syslog(LOG_ERR,"Could not open config file '%s' for reading\n",filename);
                return ERROR;
	        }

        line=0;
        while(fgets(input_buffer,MAX_INPUT_BUFFER-1,fp)){

                line++;

                /* skip comments and blank lines */
                if(input_buffer[0]=='#')
                        continue;
                if(input_buffer[0]=='\0')
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
                        if((server_port<1024 && (geteuid()!=0)) || server_port<0){
                                syslog(LOG_ERR,"Invalid port number specified in config file '%s' - Line %d\n",filename,line);
                                return ERROR;
                                }
                        }
		else if(!strcmp(varname,"server_address")){
                        strncpy(server_address,varvalue,sizeof(server_address) - 1);
                        server_address[sizeof(server_address)-1]='\0';
                        }
		else if(!strcmp(varname,"allowed_hosts")){
                        if(strlen(varvalue)>sizeof(allowed_hosts)-1){
                                syslog(LOG_ERR,"Allowed hosts list too long in config file '%s' - Line %d\n",filename,line);
                                return ERROR;
                                }
                        strncpy(allowed_hosts,varvalue,sizeof(allowed_hosts));
                        allowed_hosts[sizeof(allowed_hosts)-1]='\0';
                        }
		else if(strstr(input_buffer,"command_file")){
                        if(strlen(varvalue)>sizeof(command_file)-1){
                                syslog(LOG_ERR,"Command file name is too long in config file '%s' - Line %d\n",filename,line);
                                return ERROR;
                                }
                        strncpy(command_file,varvalue,sizeof(command_file)-1);
                        command_file[sizeof(command_file)-1]='\0';
                	}
		else if(strstr(input_buffer,"alternate_dump_file")){
                        if(strlen(varvalue)>sizeof(alternate_dump_file)-1){
                                syslog(LOG_ERR,"Alternate dump file name is too long in config file '%s' - Line %d\n",filename,line);
                                return ERROR;
                                }
                        strncpy(alternate_dump_file,varvalue,sizeof(alternate_dump_file)-1);
                        alternate_dump_file[sizeof(alternate_dump_file)-1]='\0';
                	}
		else if(strstr(input_buffer,"password")){
                        if(strlen(varvalue)>sizeof(password)-1){
                                syslog(LOG_ERR,"Password is too long in config file '%s' - Line %d\n",filename,line);
                                return ERROR;
                                }
                        strncpy(password,varvalue,sizeof(password)-1);
                        password[sizeof(password)-1]='\0';
                        }
		else if(strstr(input_buffer,"decryption_method")){

                        decryption_method=atoi(varvalue);

                        switch(decryption_method){
                        case ENCRYPT_NONE:
                        case ENCRYPT_XOR:
                                break;
#ifdef HAVE_LIBMCRYPT
                        case ENCRYPT_DES:
                        case ENCRYPT_3DES:
                        case ENCRYPT_CAST128:
                        case ENCRYPT_CAST256:
                        case ENCRYPT_XTEA:
                        case ENCRYPT_3WAY:
                        case ENCRYPT_BLOWFISH:
                        case ENCRYPT_TWOFISH:
                        case ENCRYPT_LOKI97:
                        case ENCRYPT_RC2:
                        case ENCRYPT_ARCFOUR:
                        case ENCRYPT_RIJNDAEL128:
                        case ENCRYPT_RIJNDAEL192:
                        case ENCRYPT_RIJNDAEL256:
                        case ENCRYPT_WAKE:
                        case ENCRYPT_SERPENT:
                        case ENCRYPT_ENIGMA:
                        case ENCRYPT_GOST:
                        case ENCRYPT_SAFER64:
                        case ENCRYPT_SAFER128:
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
		else if(strstr(input_buffer,"append_to_file")){
                        if(atoi(varvalue)>0)
                                append_to_file=TRUE;
                        else 
                                append_to_file=FALSE;
                        }
		else if(!strcmp(varname,"max_packet_age")){
                        max_packet_age=strtoul(varvalue,NULL,10);
                        if(max_packet_age>900){
                                syslog(LOG_ERR,"Max packet age cannot be greater than 15 minutes (900 seconds).\n");
                                return ERROR;
                                }
                        }

                else if(!strcmp(varname,"nsca_user"))
			nsca_user=strdup(varvalue);

                else if(!strcmp(varname,"nsca_group"))
			nsca_group=strdup(varvalue);

		else{
                        syslog(LOG_ERR,"Unknown option specified in config file '%s' - Line %d\n",filename,line);

                        return ERROR;
                        }
                }

        /* close the config file */
        fclose(fp);

        return OK;
        }



/* get rid of all the children we can... */
static void reap_children(int sig){

        while(waitpid(-1,NULL,WNOHANG)>0);

	return;
        }



/* install reap_children() signal handler */
static void install_child_handler(void){
        struct sigaction sa;

        sa.sa_handler=reap_children;
        sa.sa_flags=SA_NOCLDSTOP;
        sigaction(SIGCHLD,&sa,NULL);

	return;
        }



/* register a file descriptor to be polled for an event set */
static void register_poll(short events, int fd){
        int i;

        /* if it's already in the list, just flag the events */
        for(i=0;i<npfds;i++){
                if(pfds[i].fd==fd){
                        pfds[i].events|=events;
                        return;
                        }
                }

        /* else add it to the list */
        if(maxpfds==0){
                maxpfds++;
                pfds=malloc(sizeof(struct pollfd));
                }
	else if(npfds+1 > maxpfds){
                maxpfds++;
                pfds=realloc(pfds, sizeof(struct pollfd) * maxpfds);
                }

        pfds[npfds].fd=fd;
        pfds[npfds].events=events;
        npfds++;
        }



/* register a read handler */
static void register_read_handler(int fd, void (*fp)(int, void *), void *data){
        int i;

        /* register our interest in this descriptor */
        register_poll(POLLIN,fd);

        /* if it's already in the list, just update the handler */
        for(i=0;i<nrhand;i++){
                if(rhand[i].fd==fd){
                        rhand[i].handler=fp;
                        rhand[i].data=data;
                        return;
                        }
                }

        /* else add it to the list */
        if(maxrhand==0){
                maxrhand++;
                rhand=malloc(sizeof(struct handler_entry));
                }
	else if(nrhand+1 > maxrhand){
                maxrhand++;
                rhand=realloc(rhand, sizeof(struct handler_entry) * maxrhand);
                }

        rhand[nrhand].fd=fd;
        rhand[nrhand].handler=fp;
        rhand[nrhand].data=data;
        nrhand++;
        }



/* register a write handler */
static void register_write_handler(int fd, void (*fp)(int, void *), void *data){
        int i;

        /* register our interest in this descriptor */
        register_poll(POLLOUT,fd);

        /* if it's already in the list, just update the handler */
        for(i=0;i<nwhand;i++){
                if(whand[i].fd==fd){
                        whand[i].handler=fp;
                        whand[i].data=data;
                        return;
                        }
                }

        /* else add it to the list */
        if(maxwhand==0){
                maxwhand++;
                whand=malloc(sizeof(struct handler_entry));
                }
	else if(nwhand+1 > maxwhand){
                maxwhand++;
                whand=realloc(whand, sizeof(struct handler_entry) * maxwhand);
                }

        whand[nwhand].fd=fd;
        whand[nwhand].handler=fp;
        whand[nwhand].data=data;
        nwhand++;
        }



/* find read handler */
static int find_rhand(int fd){
        int i;

        for(i=0;i<nrhand;i++){
                if(rhand[i].fd==fd)
                        return i;
                }

	/* we couldn't find the read handler */
        syslog(LOG_ERR, "Handler stack corrupt - aborting");
        do_exit(STATE_CRITICAL);
        }



/* find write handler */
static int find_whand(int fd){
        int i;

        for(i=0;i<nwhand;i++){
                if(whand[i].fd==fd)
                        return i;
                }

	/* we couldn't find the write handler */
        syslog(LOG_ERR, "Handler stack corrupt - aborting");
        do_exit(STATE_CRITICAL);
        }


/* handle pending events */
static void handle_events(void){
        void (*handler)(int, void *);
        void *data;
        int i, hand;
        
        poll(pfds,npfds,-1);
        for(i=0;i<npfds;i++){
                if((pfds[i].events&POLLIN) && (pfds[i].revents&(POLLIN|POLLERR|POLLHUP|POLLNVAL))){
                        pfds[i].events&=~POLLIN;
                        hand=find_rhand(pfds[i].fd);
                        handler=rhand[hand].handler;
                        data=rhand[hand].data;
                        rhand[hand].handler=NULL;
                        rhand[hand].data=NULL;
                        handler(pfds[i].fd,data);
                        }
                if((pfds[i].events&POLLOUT) && (pfds[i].revents&(POLLOUT|POLLERR|POLLHUP|POLLNVAL))){
                        pfds[i].events&=~POLLOUT;
                        hand=find_whand(pfds[i].fd);
                        handler=whand[hand].handler;
                        data=whand[hand].data;
                        whand[hand].handler=NULL;
                        whand[hand].data=NULL;
                        handler(pfds[i].fd,data);
                        }
                }

        for(i=0;i<npfds;i++){
                if(pfds[i].events==0){
                        npfds--;
                        pfds[i].fd=pfds[npfds].fd;
                        pfds[i].events=pfds[npfds].events;
                        }
                }

	return;
        }



/* wait for incoming connection requests */
static void wait_for_connections(void) {
        struct sockaddr_in myname;
        int sock;
        int flag=1;

        /* create a socket for listening */
        sock=socket(AF_INET,SOCK_STREAM,0);

        /* exit if we couldn't create the socket */
        if(sock<0){
                syslog(LOG_ERR,"Network server socket failure (%d: %s)",errno,strerror(errno));
                do_exit(STATE_CRITICAL);
                }

        /* set the reuse address flag so we don't get errors when restarting */
        flag=1;
        if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char *)&flag,sizeof(flag))<0){
                syslog(LOG_ERR,"Could not set reuse address option on socket!\n");
                do_exit(STATE_CRITICAL);
                }

        myname.sin_family=AF_INET;
        myname.sin_port=htons(server_port);
        bzero(&myname.sin_zero,8);

        /* what address should we bind to? */
        if(!strlen(server_address))
                myname.sin_addr.s_addr=INADDR_ANY;
        else if(!my_inet_aton(server_address,&myname.sin_addr)){
                syslog(LOG_ERR,"Server address is not a valid IP address\n");
                do_exit(STATE_CRITICAL);
                }


        /* bind the address to the Internet socket */
        if(bind(sock,(struct sockaddr *)&myname,sizeof(myname))<0){
                syslog(LOG_ERR,"Network server bind failure (%d: %s)\n",errno,strerror(errno));
                do_exit(STATE_CRITICAL);
                }

        /* open the socket for listening */
        if(listen(sock,SOMAXCONN)<0){
                syslog(LOG_ERR,"Network server listen failure (%d: %s)\n",errno,strerror(errno));
                do_exit(STATE_CRITICAL);
                }

        /* log info to syslog facility */
        syslog(LOG_NOTICE,"Starting up daemon");

        if(debug==TRUE){
                syslog(LOG_DEBUG,"Listening for connections on port %d\n",htons(myname.sin_port));
                syslog(LOG_DEBUG,"Allowing connections from: %s\n",allowed_hosts);
                }

        /* listen for connection requests */
        if(mode==MULTI_PROCESS_DAEMON){
                while(1)
                        accept_connection(sock,NULL);
                }
	else{
                register_read_handler(sock,accept_connection,NULL);
                while(1)
                        handle_events();
                }

	return;
        }



static void accept_connection(int sock, void *unused){
        int new_sd;
        pid_t pid;
        struct sockaddr addr;
        struct sockaddr_in *nptr;
        int addrlen;
        int rc;
        char connecting_host[16];

        if(mode==SINGLE_PROCESS_DAEMON)
                register_read_handler(sock, accept_connection, NULL);

        /* wait for a connection request */
        while(1){
                new_sd=accept(sock,0,0);
                if(new_sd>=0)
                        break;
                if(errno==EWOULDBLOCK || errno==EINTR){
                        if(mode==MULTI_PROCESS_DAEMON)
                                sleep(1);
                        else
                                return;
                        }
		else
                        break;
                }

        /* hey, there was an error... */
        if(new_sd<0){

                /* log error to syslog facility */
                syslog(LOG_ERR,"Network server accept failure (%d: %s)",errno,strerror(errno));

                /* close socket prior to exiting */
                close(sock);
                do_exit(STATE_CRITICAL);
                }

        /* fork() if we have to... */
        if(mode==MULTI_PROCESS_DAEMON){

                pid=fork();
                if(pid){
                        /* parent doesn't need the new connection */
                        close(new_sd);
                        return;
                        }
		else{
                        /* child does not need to listen for connections */
                        close(sock);
                        }
                }

        /* find out who just connected... */
        addrlen=sizeof(addr);
        rc=getpeername(new_sd,&addr,&addrlen);

        if(rc<0){
                /* log error to syslog facility */
                syslog(LOG_ERR,"Error: Network server getpeername() failure (%d: %s)",errno,strerror(errno));

                /* close socket prior to exiting */
                close(new_sd);

                do_exit(STATE_CRITICAL);
                }

        nptr=(struct sockaddr_in *)&addr;

        /* log info to syslog facility */
        if(debug==TRUE)
                syslog(LOG_DEBUG,"Connection from %s port %d",inet_ntoa(nptr->sin_addr),nptr->sin_port);

        /* is this is blessed machine? */
        snprintf(connecting_host,sizeof(connecting_host),"%s",inet_ntoa(nptr->sin_addr));
        connecting_host[sizeof(connecting_host)-1]='\0';

        if(!is_an_allowed_host(connecting_host)){

                /* log error to syslog facility */
                syslog(LOG_ERR,"Host %s is not allowed to talk to us!", inet_ntoa(nptr->sin_addr));
                }
	else{

                /* log info to syslog facility */
                if(debug==TRUE)
                        syslog(LOG_DEBUG,"Host address checks out ok");

                if(mode==SINGLE_PROCESS_DAEMON)
                        /* mark the connection as ready to be handled */
                        register_write_handler(new_sd, handle_connection, NULL);
                else
                        /* handle the client connection */
                        handle_connection(new_sd, NULL);
                }
        }



/* handle a client connection */
static void handle_connection(int sock, void *data){
        init_packet send_packet;
        int bytes_to_send;
        int rc;
        int flags;
        time_t packet_send_time;
        struct crypt_instance *CI;


        /* log info to syslog facility */
        if(debug==TRUE)
                syslog(LOG_INFO,"Handling the connection...");

        /* socket should be non-blocking */
        fcntl(sock,F_GETFL,&flags);
        fcntl(sock,F_SETFL,flags|O_NONBLOCK);

        /* initialize encryption/decryption routines (server generates the IV to use and send to the client) */
        if(encrypt_init(password,decryption_method,NULL,&CI)!=OK){
                close(sock);
                return;
                }

        /* create initial packet to send to client (contains random IV and timestamp) */
        memcpy(&send_packet.iv[0],CI->transmitted_iv,TRANSMITTED_IV_SIZE);
        time(&packet_send_time);
        send_packet.timestamp=(u_int32_t)htonl(packet_send_time);

        /* send client the initial packet */
        bytes_to_send=sizeof(send_packet);
        rc=sendall(sock,(char *)&send_packet,&bytes_to_send);

        /* there was an error sending the packet */
        if(rc==-1){
                syslog(LOG_ERR,"Could not send init packet to client\n");
                encrypt_cleanup(decryption_method,CI);
                close(sock);
                return;
                }

        /* for some reason we didn't send all the bytes we were supposed to */
	else if(bytes_to_send<sizeof(send_packet)){
                syslog(LOG_ERR,"Only able to send %d of %d bytes of init packet to client\n",rc,sizeof(send_packet));
                encrypt_cleanup(decryption_method,CI);
                close(sock);
                return;
                }

        /* open the command file if we're aggregating writes */
        if(aggregate_writes==TRUE && !command_file_fp){
                if(open_command_file()==ERROR){
                        close(sock);
                        return;
                        }
                }

        if(mode==SINGLE_PROCESS_DAEMON)
                register_read_handler(sock, handle_connection_read, (void *)CI);
        else{
                while(1)
                        handle_connection_read(sock,(void *)CI);
	        }

	return;
        }



/* handle reading from a client connection */
static void handle_connection_read(int sock, void *data){
        data_packet receive_packet;
        u_int32_t long packet_crc32;
        u_int32_t calculated_crc32;
        struct crypt_instance *CI;
        time_t packet_time;
        time_t current_time;
        int16_t return_code;
        unsigned long packet_age=0L;
        int bytes_to_recv;
        int rc;
        char host_name[MAX_HOSTNAME_LENGTH];
        char svc_description[MAX_DESCRIPTION_LENGTH];
        char plugin_output[MAX_PLUGINOUTPUT_LENGTH];

        CI=data;

        /* process all data we get from the client... */

        /* read the packet from the client */
        bytes_to_recv=sizeof(receive_packet);
        rc=recvall(sock,(char *)&receive_packet,&bytes_to_recv,socket_timeout);

        /* recv() error or client disconnect */
        if(rc<=0){
                if(debug==TRUE)
                        syslog(LOG_ERR,"End of connection or could not read request from client...");
                encrypt_cleanup(decryption_method, CI);
                close(sock);
                if (mode==SINGLE_PROCESS_DAEMON)
                        return;
                else
                        do_exit(STATE_OK);
                }

        /* we couldn't read the correct amount of data, so bail out */
        if(bytes_to_recv!=sizeof(receive_packet)){
                syslog(LOG_ERR,"Data sent from client was too short (%d < %d), aborting...",bytes_to_recv,sizeof(receive_packet));
                encrypt_cleanup(decryption_method, CI);
                close(sock);
                if(mode==SINGLE_PROCESS_DAEMON)
                        return;
                else
                        do_exit(STATE_CRITICAL);
                }

        /* if we're single-process, we need to set things up so we handle the next packet after this one... */
        if(mode==SINGLE_PROCESS_DAEMON)
                register_read_handler(sock, handle_connection_read, (void *)CI);

        /* decrypt the packet */
        decrypt_buffer((char *)&receive_packet,sizeof(receive_packet),password,decryption_method,CI);

        /* make sure this is the right type of packet */
        if(ntohs(receive_packet.packet_version)!=NSCA_PACKET_VERSION_3){
                syslog(LOG_ERR,"Received invalid packet type/version from client - possibly due to client using wrong password or crypto algorithm?");
                return;
                }

        /* check the crc 32 value */
        packet_crc32=ntohl(receive_packet.crc32_value);
        receive_packet.crc32_value=0L;
        calculated_crc32=calculate_crc32((char *)&receive_packet,sizeof(receive_packet));
        if(packet_crc32!=calculated_crc32){
                syslog(LOG_ERR,"Dropping packet with invalid CRC32 - possibly due to client using wrong password or crypto algorithm?");
                return;
                }

        /* check the timestamp in the packet */
        packet_time=(time_t)ntohl(receive_packet.timestamp);
        time(&current_time);
        if(packet_time>current_time){
                syslog(LOG_ERR,"Dropping packet with future timestamp.");
                return;
                }
	else{
                packet_age=(unsigned long)(current_time-packet_time);
                if(packet_age > max_packet_age){
                        syslog(LOG_ERR,"Dropping packet with stale timestamp - packet was %lu seconds old.",packet_age);
                        return;
                        }
                }

        /**** GET THE SERVICE CHECK INFORMATION ****/

        /* plugin return code */
        return_code=ntohs(receive_packet.return_code);

        /* host name */
        strncpy(host_name,receive_packet.host_name,sizeof(host_name)-1);
        host_name[sizeof(host_name)-1]='\0';
        
        /* service description */
        strncpy(svc_description,receive_packet.svc_description,sizeof(svc_description)-1);
        svc_description[sizeof(svc_description)-1]='\0';
        
        /* plugin output */
        strncpy(plugin_output,receive_packet.plugin_output,sizeof(plugin_output)-1);
        plugin_output[sizeof(plugin_output)-1]='\0';

        /* log info to syslog facility */
        if(debug==TRUE){
		if(!strcmp(svc_description,""))
			syslog(LOG_NOTICE,"HOST CHECK -> Host Name: '%s', Return Code: '%d', Output: '%s'",host_name,return_code,plugin_output);
		else
			syslog(LOG_NOTICE,"SERVICE CHECK -> Host Name: '%s', Service Description: '%s', Return Code: '%d', Output: '%s'",host_name,svc_description,return_code,plugin_output);
	        }

        /* write the check result to the external command file.
         * Note: it's OK to hang at this point if the write doesn't succeed, as there's
         * no way we could handle any other connection properly anyway.  so we don't
         * use poll() - which fails on a pipe with any data, so it would cause us to
         * only ever write one command at a time into the pipe.
         */
        write_check_result(host_name,svc_description,return_code,plugin_output,time(NULL));

	return;
        }



/* checks to see if a given host is allowed to talk to us */
static int is_an_allowed_host(char *connecting_host){
        char temp_buffer[MAX_INPUT_BUFFER];
        char *temp_ptr;

        strncpy(temp_buffer,allowed_hosts,sizeof(temp_buffer));
        temp_buffer[sizeof(temp_buffer)-1]='\0';

        for(temp_ptr=strtok(temp_buffer,",");temp_ptr!=NULL;temp_ptr=strtok(NULL,",")){
                if(!strcmp(connecting_host,temp_ptr))
                        return 1;
                }

        return 0;
        }


/* writes service/host check results to the Nagios command file */
static int write_check_result(char *host_name, char *svc_description, int return_code, char *plugin_output, time_t check_time){

        if(aggregate_writes==FALSE){
                if(open_command_file()==ERROR)
                        return ERROR;
                }

	if(!strcmp(svc_description,""))
		fprintf(command_file_fp,"[%lu] PROCESS_HOST_CHECK_RESULT;%s;%d;%s\n",(unsigned long)check_time,host_name,return_code,plugin_output);
	else
		fprintf(command_file_fp,"[%lu] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%d;%s\n",(unsigned long)check_time,host_name,svc_description,return_code,plugin_output);

        if(aggregate_writes==FALSE)
                close_command_file();
        else
                /* if we don't fflush() then we're writing in 4k non-CR-terminated blocks, and
                 * anything else (eg. pscwatch) which writes to the file will be writing into
                 * the middle of our commands.
                 */
                fflush(command_file_fp);
        
        return OK;
        }



/* opens the command file for writing */
static int open_command_file(void){
	struct stat statbuf;

        /* file is already open */
        if(command_file_fp!=NULL)
                return OK;

	/* command file doesn't exist - monitoring app probably isn't running... */
	if(stat(command_file,&statbuf)){
		
		if(debug==TRUE)
			syslog(LOG_ERR,"Command file '%s' does not exist, attempting to use alternate dump file '%s' for output",command_file,alternate_dump_file);

		/* try and write checks to alternate dump file */
		command_file_fp=fopen(alternate_dump_file,"a");
		if(command_file_fp==NULL){
			if(debug==TRUE)
				syslog(LOG_ERR,"Could not open alternate dump file '%s' for appending",alternate_dump_file);
			return ERROR;
                        }

		return OK;
	        }

        /* open the command file for writing or appending */
        command_file_fp=fopen(command_file,(append_to_file==TRUE)?"a":"w");
        if(command_file_fp==NULL){
                if(debug==TRUE)
                        syslog(LOG_ERR,"Could not open command file '%s' for %s",command_file,(append_to_file==TRUE)?"appending":"writing");
                return ERROR;
                }

        return OK;
        }



/* closes the command file */
static void close_command_file(void){

        fclose(command_file_fp);
        command_file_fp=NULL;

        return;
        }



/* process command line arguments */
int process_arguments(int argc, char **argv){
	int x;

	if(argc<2){
		show_help=TRUE;
		return OK;
	        }

	/* process arguments */
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

		else if(!strcmp(argv[x-1],"-d") || !strcmp(argv[x-1],"--daemon"))
                        mode=MULTI_PROCESS_DAEMON;

                else if(!strcmp(argv[x-1],"-s") || !strcmp(argv[x-1],"--single"))
                        mode=SINGLE_PROCESS_DAEMON;

                else if(!strcmp(argv[x-1],"-i") || !strcmp(argv[x-1],"--inetd"))
                        mode=INETD;

		/* config file */
		else if(!strcmp(argv[x-1],"-c")){

			if(x<argc){
				/* grab the config file */
				strncpy(config_file,argv[x],sizeof(config_file)-1);
				config_file[sizeof(config_file)-1]='\0';
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



/* drops privileges */
static int drop_privileges(char *user, char *group){
	uid_t uid=-1;
	gid_t gid=-1;
	struct group *grp;
	struct passwd *pw;

	/* set effective group ID */
	if(group!=NULL){
		
		/* see if this is a group name */
		if(strspn(group,"0123456789")<strlen(group)){
			grp=(struct group *)getgrnam(group);
			if(grp!=NULL)
				gid=(gid_t)(grp->gr_gid);
			else
				syslog(LOG_ERR,"Warning: Could not get group entry for '%s'",group);
		        }

		/* else we were passed the GID */
		else
			gid=(gid_t)atoi(group);

		/* set effective group ID if other than current EGID */
		if(gid!=getegid()){

			if(setgid(gid)==-1)
				syslog(LOG_ERR,"Warning: Could not set effective GID=%d",(int)gid);
		        }
	        }


	/* set effective user ID */
	if(user!=NULL){
		
		/* see if this is a user name */
		if(strspn(user,"0123456789")<strlen(user)){
			pw=(struct passwd *)getpwnam(user);
			if(pw!=NULL)
				uid=(uid_t)(pw->pw_uid);
			else
				syslog(LOG_ERR,"Warning: Could not get passwd entry for '%s'",user);
		        }

		/* else we were passed the UID */
		else
			uid=(uid_t)atoi(user);
			
#ifdef HAVE_INITGROUPS

		if(uid!=geteuid()){

			/* initialize supplementary groups */
			if(initgroups(user,gid)==-1){
				if(errno==EPERM)
					syslog(LOG_ERR,"Warning: Unable to change supplementary groups using initgroups()");
				else{
					syslog(LOG_ERR,"Warning: Possibly root user failed dropping privileges with initgroups()");
					return ERROR;
			                }
	                        }
		        }
#endif

		if(setuid(uid)==-1)
			syslog(LOG_ERR,"Warning: Could not set effective UID=%d",(int)uid);
	        }

	return OK;
        }
