/*******************************************************************************
 *
 * NSCA.C - Nagios Service Check Acceptor
 * Copyright (c) 2009 Nagios Core Development Team and Community Contributors
 * Copyright (c) 2000-2009 Ethan Galstad (egalstad@nagios.org)
 * License: GPL v2
 *
 * Last Modified: 01-27-2012
 *
 * Command line: NSCA -c <config_file> [mode]
 *
 * Description:
 *
 * This program is designed to run as a daemon on the main Nagios machine 
 * and accept service check results from remote hosts.
 * 
 ******************************************************************************/

#include "../include/common.h"
#include "../include/config.h"
#include "../include/netutils.h"
#include "../include/utils.h"
#include "../include/nsca.h"


static int server_port=DEFAULT_SERVER_PORT;
static char server_address[16]="0.0.0.0";
static int socket_timeout=DEFAULT_SOCKET_TIMEOUT;
static int log_facility=LOG_DAEMON;

static char config_file[MAX_INPUT_BUFFER]="nsca.cfg";
static char alternate_dump_file[MAX_INPUT_BUFFER]="/dev/null";
static char command_file[MAX_INPUT_BUFFER]="";
static char password[MAX_INPUT_BUFFER]="";

static enum { OPTIONS_ERROR, SINGLE_PROCESS_DAEMON, MULTI_PROCESS_DAEMON, INETD } mode=SINGLE_PROCESS_DAEMON;
static int debug=FALSE;
static int aggregate_writes=FALSE;
static int decryption_method=ENCRYPT_XOR;
static int append_to_file=FALSE;
static unsigned long max_packet_age=30;

char    *nsca_user=NULL;
char    *nsca_group=NULL;

char    *nsca_chroot=NULL;
char    *check_result_path=NULL;


char    *pid_file=NULL;
int     wrote_pid_file=FALSE;

int     show_help=FALSE;
int     show_license=FALSE;
int     show_version=FALSE;

int     sigrestart=FALSE;
int     sigshutdown=FALSE;

int	using_alternate_dump_file=FALSE;
static FILE *command_file_fp=NULL;

struct handler_entry *rhand=NULL;
struct handler_entry *whand=NULL;
struct pollfd *pfds=NULL;
int     maxrhand=0;
int     maxwhand=0;
int     maxpfds=0;
int     nrhand=0;
int     nwhand=0;
int     npfds=0;
	
#ifdef HAVE_LIBWRAP
int     allow_severity=LOG_INFO;
int     deny_severity=LOG_WARNING;
#endif



int main(int argc, char **argv){
        char buffer[MAX_INPUT_BUFFER];
        int result;
        uid_t uid=-1;
        gid_t gid=-1;


	/* process command-line arguments */
	result=process_arguments(argc,argv);

        if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE){

		if(result!=OK)
			printf("Incorrect command line arguments supplied\n");
                printf("\n");
                printf("NSCA - Nagios Service Check Acceptor\n");
		printf("Copyright (c) 2009 Nagios Core Development Team and Community Contributors\n");
                printf("Copyright (c) 2000-2009 Ethan Galstad\n");
                printf("Version: %s\n",PROGRAM_VERSION);
                printf("Last Modified: %s\n",MODIFICATION_DATE);
                printf("License: GPL v2\n");
                printf("Encryption Routines: ");
#ifdef HAVE_LIBMCRYPT
                printf("AVAILABLE");
#else
                printf("NOT AVAILABLE");
#endif          
                printf("\n");
#ifdef HAVE_LIBWRAP
		printf("TCP Wrappers Available\n");
#endif
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
                printf("This program is designed to accept passive check results from\n");
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
	/* facility may be overridden later */
	get_log_facility(NSCA_LOG_FACILITY);
        openlog("nsca",LOG_PID|LOG_NDELAY,log_facility); 

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
		/* chroot if configured */
		do_chroot();

                /* if we're running under inetd, handle one connection and get out */
                handle_connection(0,NULL);
                break;

        case MULTI_PROCESS_DAEMON:

		/* older style, mult-process daemon */
		/* execution cascades below... */
                install_child_handler();

		/*     |
		       |
		       |     */
        case SINGLE_PROCESS_DAEMON:
		/*     |
		       |
		       V     */

                /* daemonize and start listening for requests... */
                if(fork()==0){

                        /* we're a daemon - set up a new process group */
                        setsid();

			/* handle signals */
			signal(SIGQUIT,sighandler);
			signal(SIGTERM,sighandler);
			signal(SIGHUP,sighandler);

			/* close standard file descriptors */
                        close(0);
                        close(1);
                        close(2);

			/* redirect standard descriptors to /dev/null */
			open("/dev/null",O_RDONLY);
			open("/dev/null",O_WRONLY);
			open("/dev/null",O_WRONLY);

			/* get group information before chrooting */
			get_user_info(nsca_user,&uid);
			get_group_info(nsca_group,&gid);

			/* write pid file */
			if(write_pid_file(uid,gid)==ERROR)
				return STATE_CRITICAL;
		
			/* chroot if configured */
			do_chroot();

			/* drop privileges */
			if(drop_privileges(nsca_user,uid,gid)==ERROR)
				do_exit(STATE_CRITICAL);

			do{

				/* reset flags */
				sigrestart=FALSE;
				sigshutdown=FALSE;

				/* wait for connections */
				wait_for_connections();

				if(sigrestart==TRUE){

					/* free memory */
					free_memory();

					/* re-read the config file */
					result=read_config_file(config_file);	

					/* exit if there are errors... */
					if(result==ERROR){
						syslog(LOG_ERR,"Config file '%s' contained errors, bailing out...",config_file);
						break;
						}
					}
	
				}while(sigrestart==TRUE && sigshutdown==FALSE);

			/* remove pid file */
			remove_pid_file();

			syslog(LOG_NOTICE,"Daemon shutdown\n");
		        }
                break;

        default:
                break;
	        }
	
	/* we are now running in daemon mode, or the connection handed over by inetd has been completed, so the parent process exits */
        do_exit(STATE_OK);

	/* keep the compilers happy... */
	return STATE_OK;
	}


/* cleanup */
static void do_cleanup(void){

	/* free memory */
	free_memory();

        /* close the command file if its still open */
        if(command_file_fp!=NULL)
                close_command_file();

 	/*** CLEAR SENSITIVE INFO FROM MEMORY ***/

        /* overwrite password */
        clear_buffer(password,sizeof(password));

	/* disguise decryption method */
	decryption_method=-1;

	return;
        }


/* free some memory */
static void free_memory(void){

	if(nsca_user){
		free(nsca_user);
		nsca_user=NULL;
		}
	if(nsca_group){
		free(nsca_group);
		nsca_group=NULL;
		}
	if(nsca_chroot){
		free(nsca_chroot);
		nsca_chroot=NULL;
		}
	if(pid_file){
		free(pid_file);
		pid_file=NULL;
		}

	return;
	}



/* exit cleanly */
static void do_exit(int return_code){

	do_cleanup();

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
                    else if(strstr(input_buffer,"check_result_path")){
                            if(strlen(varvalue)>MAX_INPUT_BUFFER-1){
                                    syslog(LOG_ERR,"Check result path is too long in config file '%s' - Line %d\n",filename,line);
                                    return ERROR;
                                    }
                            check_result_path=strdup(varvalue);
                            
                            int checkresult_test_fd=-1;
                            char *checkresult_test=NULL;
                            asprintf(&checkresult_test,"%s/nsca.test.%i",check_result_path,getpid());
                            checkresult_test_fd=open(checkresult_test,O_WRONLY|O_CREAT);
                            if (checkresult_test_fd>0){
                                    unlink(checkresult_test);
                                    }
                            else {
                                    printf("error!\n");
                                    syslog(LOG_ERR,"check_result_path config variable found, but directory not writeable.\n");
                                    return ERROR;
                                    }
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

                else if(!strcmp(varname,"nsca_chroot"))
			nsca_chroot=strdup(varvalue);

		else if(!strcmp(varname,"pid_file"))
			pid_file=strdup(varvalue);

		else if(!strcmp(varname,"log_facility")){
			if((get_log_facility(varvalue))==OK){
				/* re-open log using new facility */
				closelog();
				openlog("nsca",LOG_PID|LOG_NDELAY,log_facility); 
				}
			else
				syslog(LOG_WARNING,"Invalid log_facility specified in config file '%s' - Line %d\n",filename,line);
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



/* determines facility to use with syslog */
int get_log_facility(char *varvalue){

	if(!strcmp(varvalue,"kern"))
		log_facility=LOG_KERN;
	else if(!strcmp(varvalue,"user"))
		log_facility=LOG_USER;
	else if(!strcmp(varvalue,"mail"))
		log_facility=LOG_MAIL;
	else if(!strcmp(varvalue,"daemon"))
		log_facility=LOG_DAEMON;
	else if(!strcmp(varvalue,"auth"))
		log_facility=LOG_AUTH;
	else if(!strcmp(varvalue,"syslog"))
		log_facility=LOG_SYSLOG;
	else if(!strcmp(varvalue,"lrp"))
		log_facility=LOG_LPR;
	else if(!strcmp(varvalue,"news"))
		log_facility=LOG_NEWS;
	else if(!strcmp(varvalue,"uucp"))
		log_facility=LOG_UUCP;
	else if(!strcmp(varvalue,"cron"))
		log_facility=LOG_CRON;
	else if(!strcmp(varvalue,"authpriv"))
		log_facility=LOG_AUTHPRIV;
	else if(!strcmp(varvalue,"ftp"))
		log_facility=LOG_FTP;
	else if(!strcmp(varvalue,"local0"))
		log_facility=LOG_LOCAL0;
	else if(!strcmp(varvalue,"local1"))
		log_facility=LOG_LOCAL1;
	else if(!strcmp(varvalue,"local2"))
		log_facility=LOG_LOCAL2;
	else if(!strcmp(varvalue,"local3"))
		log_facility=LOG_LOCAL3;
	else if(!strcmp(varvalue,"local4"))
		log_facility=LOG_LOCAL4;
	else if(!strcmp(varvalue,"local5"))
		log_facility=LOG_LOCAL5;
	else if(!strcmp(varvalue,"local6"))
		log_facility=LOG_LOCAL6;
	else if(!strcmp(varvalue,"local7"))
		log_facility=LOG_LOCAL7;
	else{
		log_facility=LOG_DAEMON;
		return ERROR;
		}

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
        
	/* bail out if necessary */
	if(sigrestart==TRUE || sigshutdown==TRUE)
		return;

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
        int sock=0;
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
                }

	/* socket should be non-blocking for mult-process daemon */
	if(mode==MULTI_PROCESS_DAEMON)
		fcntl(sock,F_SETFL,O_NONBLOCK);

        /* listen for connection requests */
        if(mode==SINGLE_PROCESS_DAEMON)
                register_read_handler(sock,accept_connection,NULL);
	while(1){

		/* bail out if necessary */
		if(sigrestart==TRUE || sigshutdown==TRUE){
			/* close the socket we're listening on */
			close(sock);
			break;
			}

		/* accept a new connection */
		if(mode==MULTI_PROCESS_DAEMON)
			accept_connection(sock,NULL);

		/* handle the new connection (if any) */
		else
                        handle_events();
                }

	return;
        }



static void accept_connection(int sock, void *unused){
        int new_sd;
        pid_t pid;
        struct sockaddr addr;
        struct sockaddr_in *nptr;
        socklen_t addrlen;
        int rc;
#ifdef HAVE_LIBWRAP
	struct request_info req;
#endif

	/* DO NOT REMOVE! 01/29/2007 single process daemon will fail if this is removed */
        if(mode==SINGLE_PROCESS_DAEMON)
                register_read_handler(sock,accept_connection,NULL);

        /* wait for a connection request */
        while(1){

		/* we got a live one... */
                if((new_sd=accept(sock,0,0))>=0)
                        break;

		/* handle the error */
		else{

			/* bail out if necessary */
			if(sigrestart==TRUE || sigshutdown==TRUE)
				return;

			/* try and handle temporary errors */
			if(errno==EWOULDBLOCK || errno==EINTR || errno==ECHILD){
				if(mode==MULTI_PROCESS_DAEMON)
					sleep(1);
				else
					return;
				}
			else
				break;
			}
                }

        /* hey, there was an error... */
        if(new_sd<0){

                /* log error to syslog facility */
                syslog(LOG_ERR,"Network server accept failure (%d: %s)",errno,strerror(errno));

                /* close socket prior to exiting */
                close(sock);
		if(mode==MULTI_PROCESS_DAEMON)
			do_exit(STATE_CRITICAL);
		return;
                }

#ifdef HAVE_LIBWRAP

	/* Check whether or not connections are allowed from this host */
	request_init(&req,RQ_DAEMON,"nsca",RQ_FILE,new_sd,0);
	fromhost(&req);

	if(!hosts_access(&req)){
		/* refuse the connection */
		syslog(LOG_ERR, "refused connect from %s", eval_client(&req));
		close(new_sd);
		return;
		}
#endif


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
		if(mode==MULTI_PROCESS_DAEMON)
			do_exit(STATE_CRITICAL);
		return;
                }

        nptr=(struct sockaddr_in *)&addr;

        /* log info to syslog facility */
        if(debug==TRUE)
                syslog(LOG_DEBUG,"Connection from %s port %d",inet_ntoa(nptr->sin_addr),nptr->sin_port);

	/* handle the connection */
	if(mode==SINGLE_PROCESS_DAEMON)
		/* mark the connection as ready to be handled */
		register_write_handler(new_sd, handle_connection, NULL);
	else
		/* handle the client connection */
		handle_connection(new_sd, NULL);

	return;
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
		if(mode==MULTI_PROCESS_DAEMON)
			do_exit(STATE_CRITICAL);
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
		if(mode==MULTI_PROCESS_DAEMON)
			do_exit(STATE_CRITICAL);
                return;
                }

        /* for some reason we didn't send all the bytes we were supposed to */
	else if(bytes_to_send<sizeof(send_packet)){
                syslog(LOG_ERR,"Only able to send %d of %d bytes of init packet to client\n",rc,sizeof(send_packet));
                encrypt_cleanup(decryption_method,CI);
                close(sock);
		if(mode==MULTI_PROCESS_DAEMON)
			do_exit(STATE_CRITICAL);
                return;
                }

        /* open the command file if we're aggregating writes */
        if(aggregate_writes==TRUE){
                if(open_command_file()==ERROR){
                        close(sock);
			if(mode==MULTI_PROCESS_DAEMON)
				do_exit(STATE_CRITICAL);
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
        u_int32_t packet_crc32;
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
        int packet_length=sizeof(receive_packet);
        int plugin_length=MAX_PLUGINOUTPUT_LENGTH;

        CI=data;

        /* process all data we get from the client... */

        /* read the packet from the client */
        bytes_to_recv=sizeof(receive_packet);
        rc=recvall(sock,(char *)&receive_packet,&bytes_to_recv,socket_timeout);

        /* recv() error or client disconnect */
        if(rc<=0){
                if( OLD_PACKET_LENGTH == bytes_to_recv){
                        packet_length=OLD_PACKET_LENGTH;
                        plugin_length=OLD_PLUGINOUTPUT_LENGTH;
                        }
				else {
                        if(debug==TRUE)
                                syslog(LOG_ERR,"End of connection...");
                        encrypt_cleanup(decryption_method, CI);
                        close(sock);
                        if(mode==SINGLE_PROCESS_DAEMON)
                                return;
                        else
                                do_exit(STATE_OK);
                        }
                }

        /* we couldn't read the correct amount of data, so bail out */
        if(bytes_to_recv!=packet_length){
                syslog(LOG_ERR,"Data sent from client was too short (%d < %d), aborting...",bytes_to_recv,packet_length);
                encrypt_cleanup(decryption_method, CI);
                close(sock);
		return;
                if(mode==SINGLE_PROCESS_DAEMON)
                        return;
                else
                        do_exit(STATE_CRITICAL);
                }

        /* if we're single-process, we need to set things up so we handle the next packet after this one... */
        if(mode==SINGLE_PROCESS_DAEMON)
                register_read_handler(sock, handle_connection_read, (void *)CI);

        /* decrypt the packet */
        decrypt_buffer((char *)&receive_packet,packet_length,password,decryption_method,CI);

        /* make sure this is the right type of packet */
        if(ntohs(receive_packet.packet_version)!=NSCA_PACKET_VERSION_3){
                syslog(LOG_ERR,"Received invalid packet type/version from client - possibly due to client using wrong password or crypto algorithm?");
		/*return;*/
		close(sock);
                if(mode==SINGLE_PROCESS_DAEMON)
                        return;
                else
                        do_exit(STATE_OK);
                }

        /* check the crc 32 value */
        packet_crc32=ntohl(receive_packet.crc32_value);
        receive_packet.crc32_value=0L;
        calculated_crc32=calculate_crc32((char *)&receive_packet,packet_length);
        if(packet_crc32!=calculated_crc32){
                syslog(LOG_ERR,"Dropping packet with invalid CRC32 - possibly due to client using wrong password or crypto algorithm?");
                /*return;*/
		close(sock);
                if(mode==SINGLE_PROCESS_DAEMON)
                        return;
                else
                        do_exit(STATE_OK);
                 }

        /* host name */
        strncpy(host_name,receive_packet.host_name,sizeof(host_name)-1);
        host_name[sizeof(host_name)-1]='\0';

        packet_age=(unsigned long)(current_time-packet_time);
        if(debug==TRUE)
                  syslog(LOG_ERR,"Time difference in packet: %lu seconds for host %s", packet_age, host_name);
        if((max_packet_age>0 && (packet_age>max_packet_age) && (packet_age>=0)) ||
                ((max_packet_age>0) && (packet_age<(0-max_packet_age)) && (packet_age < 0))
        ){
                syslog(LOG_ERR,"Dropping packet with stale timestamp for %s - packet was %lu seconds old.",host_name,packet_age);
		close(sock);
                if(mode==SINGLE_PROCESS_DAEMON)
                        return;
                else
                        do_exit(STATE_OK);
        }

        /**** GET THE SERVICE CHECK INFORMATION ****/

        /* plugin return code */
        return_code=ntohs(receive_packet.return_code);

        /* service description */
        strncpy(svc_description,receive_packet.svc_description,sizeof(svc_description)-1);
        svc_description[sizeof(svc_description)-1]='\0';
        
        /* plugin output */
        strncpy(plugin_output,receive_packet.plugin_output,plugin_length-1);
        plugin_output[plugin_length-1]='\0';

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
        //syslog(LOG_ERR,"'%s' (%s) []",check_result_path, strlen(check_result_path));
        if (check_result_path==NULL){
        write_check_result(host_name,svc_description,return_code,plugin_output,time(NULL));
        }else{
                write_checkresult_file(host_name,svc_description,return_code,plugin_output,time(NULL));
        }

	return;
        }



/* writes service/host check results to the Nagios checkresult directory */
static int write_checkresult_file(char *host_name, char *svc_description, int return_code, char *plugin_output, time_t check_time){
	if(debug==TRUE)
		syslog(LOG_ERR,"Attempting to write checkresult file");
        mode_t new_umask=077;
        mode_t old_umask;
        time_t current_time;
        char *output_file=NULL;
        int checkresult_file_fd=-1;
        char *checkresult_file=NULL;
        char *checkresult_ok_file=NULL;
        FILE *checkresult_file_fp=NULL;
        FILE *checkresult_ok_file_fp=NULL;
        /* change and store umask */
        old_umask=umask(new_umask);

        /* create safe checkresult file */
        asprintf(&checkresult_file,"%s/cXXXXXX",check_result_path);
        checkresult_file_fd=mkstemp(checkresult_file);
        if(checkresult_file_fd>0){
                checkresult_file_fp=fdopen(checkresult_file_fd,"w");
        } else {
                syslog(LOG_ERR,"Unable to open and write checkresult file '%s', failing back to PIPE",checkresult_file);
                return write_check_result(host_name,svc_description,return_code,plugin_output,check_time);
                }
        
	if(debug==TRUE)
		syslog(LOG_ERR,"checkresult file '%s' open for write.",checkresult_file);

        time(&current_time);
        fprintf(checkresult_file_fp,"### NSCA Passive Check Result ###\n");
        fprintf(checkresult_file_fp,"# Time: %s",ctime(&current_time));
        fprintf(checkresult_file_fp,"file_time=%d\n\n",current_time);
        fprintf(checkresult_file_fp,"### %s Check Result ###\n",(svc_description=="")?"Host":"Service");
        fprintf(checkresult_file_fp,"host_name=%s\n",host_name);
        if(strcmp(svc_description,""))
                fprintf(checkresult_file_fp,"service_description=%s\n",svc_description);
        fprintf(checkresult_file_fp,"check_type=1\n");
        fprintf(checkresult_file_fp,"scheduled_check=0\n");
        fprintf(checkresult_file_fp,"reschedule_check=0\n");
        /* We have no latency data at this point. */
        fprintf(checkresult_file_fp,"latency=0\n");
        fprintf(checkresult_file_fp,"start_time=%lu.%lu\n",check_time,0L);
        fprintf(checkresult_file_fp,"finish_time=%lu.%lu\n",check_time,0L);
        fprintf(checkresult_file_fp,"return_code=%d\n",return_code);
        /* newlines in output are already escaped */
        fprintf(checkresult_file_fp,"output=%s\n",(plugin_output==NULL)?"":plugin_output);
        fprintf(checkresult_file_fp,"\n");

        fclose(checkresult_file_fp);
        /* create and close ok file */
        asprintf(&checkresult_ok_file,"%s.ok",checkresult_file);
        syslog(LOG_DEBUG,"checkresult completion file '%s' open.",checkresult_ok_file);
        checkresult_ok_file_fp = fopen(checkresult_ok_file,"w");
        fclose(checkresult_ok_file_fp);
        /* reset umask */
        umask(old_umask);

        return OK;
        }

/* writes service/host check results to the Nagios command file */
static int write_check_result(char *host_name, char *svc_description, int return_code, char *plugin_output, time_t check_time){
	if(debug==TRUE)
		syslog(LOG_ERR,"Attempting to write to nagios command pipe");
        if(aggregate_writes==FALSE){
                if(open_command_file()==ERROR)
                        return ERROR;
                }

	if(!strcmp(svc_description,""))
		fprintf(command_file_fp,"[%lu] PROCESS_HOST_CHECK_RESULT;%s;%d;%s\n",(unsigned long)check_time,host_name,return_code,plugin_output);
	else{
		fprintf(command_file_fp,"[%lu] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%d;%s\n",(unsigned long)check_time,host_name,svc_description,return_code,plugin_output);
                }
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
        if(command_file_fp!=NULL && using_alternate_dump_file==FALSE)
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
		using_alternate_dump_file=TRUE;

		return OK;
	        }

        /* open the command file for writing or appending */
        command_file_fp=fopen(command_file,(append_to_file==TRUE)?"a":"w");
        if(command_file_fp==NULL){
                if(debug==TRUE)
                        syslog(LOG_ERR,"Could not open command file '%s' for %s",command_file,(append_to_file==TRUE)?"appending":"writing");
                return ERROR;
                }

	using_alternate_dump_file=FALSE;
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



/* write an optional pid file */
static int write_pid_file(uid_t usr, gid_t grp){
	int fd;
	int result=0;
	pid_t pid=0;
	char pbuf[16];

	/* no pid file was specified */
	if(pid_file==NULL)
		return OK;

	/* read existing pid file */
	if((fd=open(pid_file,O_RDONLY))>=0){

		result=read(fd,pbuf,(sizeof pbuf)-1);

		close(fd);

		if(result>0){

			pbuf[result]='\x0';
			pid=(pid_t)atoi(pbuf);

			/* if previous process is no longer running running, remove the old pid file */
			if(pid && (pid==getpid() || kill(pid,0)<0))
				unlink(pid_file);

			/* previous process is still running */
			else{
				syslog(LOG_ERR,"There's already an NSCA server running (PID %lu).  Bailing out...",(unsigned long)pid);
				return ERROR;
			        }
		        }
	        } 

	/* write new pid file */
	if((fd=open(pid_file,O_WRONLY | O_CREAT,0644))>=0){
		sprintf(pbuf,"%d\n",(int)getpid());
		write(fd,pbuf,strlen(pbuf));
		fchown(fd,usr,grp);
		close(fd);
		wrote_pid_file=TRUE;
	        }
	else{
		syslog(LOG_ERR,"Cannot write to pidfile '%s' - check your privileges.",pid_file);
	        }

	return OK;
        }



/* remove pid file */
static int remove_pid_file(void){

	/* no pid file was specified */
	if(pid_file==NULL)
		return OK;

	/* pid file was not written */
	if(wrote_pid_file==FALSE)
		return OK;

	/* remove existing pid file */
	if(unlink(pid_file)==-1){
		syslog(LOG_ERR,"Cannot remove pidfile '%s' - check your privileges.",pid_file);
		return ERROR;
	        }

	return OK;
        }



/* get user information */
static int get_user_info(const char *user, uid_t *uid){
	const struct passwd *pw=NULL;
	
	if(user!=NULL){
		/* see if this is a user name */
		if(strspn(user,"0123456789")<strlen(user)){
			pw=(struct passwd *)getpwnam(user);
			if(pw!=NULL)
				*uid=(uid_t)(pw->pw_uid);
			else
				syslog(LOG_ERR,"Warning: Could not get passwd entry for '%s'",user);
			endpwent();
		        }

		/* else we were passed the UID */
		else
			*uid=(uid_t)atoi(user);

	        } 
	else
		*uid=geteuid();

	return OK;
        }



/* get group information */
static int get_group_info(const char *group, gid_t *gid){
	const struct group *grp=NULL;
	
	/* get group ID */
	if(group!=NULL){
		/* see if this is a group name */
		if(strspn(group,"0123456789")<strlen(group)){
			grp=(struct group *)getgrnam(group);
			if(grp!=NULL)
				*gid=(gid_t)(grp->gr_gid);
			else
				syslog(LOG_ERR,"Warning: Could not get group entry for '%s'",group);
			endgrent();
		        }

		/* else we were passed the GID */
		else
			*gid=(gid_t)atoi(group);
	        } 
	else
		*gid=getegid();

	return OK;
        }



/* drops privileges */
static int drop_privileges(const char *user, uid_t uid, gid_t gid){
	struct group *grp;
	struct passwd *pw;

	/* only drop privileges if we're running as root, so we don't interfere with being debugged while running as some random user */
	if(getuid()!=0)
		return OK;

	/* set effective group ID if other than current EGID */
	if(gid!=getegid()){
		if(setgid(gid)==-1){
			syslog(LOG_ERR,"Warning: Could not set effective GID=%d",(int)gid);
			return ERROR;
		        }
	        }

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

	if(setuid(uid)==-1){
		syslog(LOG_ERR,"Warning: Could not set effective UID=%d",(int)uid);
		return ERROR;
	        }

	return OK;
        }



/* perform the chroot() operation if configured to do so */
void do_chroot(void){
	int retval=0;
	const char *err=NULL;

	if(nsca_chroot!=NULL){
		retval=chdir(nsca_chroot);
		if(retval!=0){
			err=strerror(errno);
			syslog(LOG_ERR, "can not chdir into chroot directory: %s", err);
			do_exit(STATE_UNKNOWN);
		        }
		retval=chroot(".");
		if(retval!=0){
			err=strerror(errno);
			syslog(LOG_ERR, "can not chroot: %s", err);
			do_exit(STATE_UNKNOWN);
		        }
	        }
        }



/* handle signals */
void sighandler(int sig){
	static char *sigs[]={"EXIT","HUP","INT","QUIT","ILL","TRAP","ABRT","BUS","FPE","KILL","USR1","SEGV","USR2","PIPE","ALRM","TERM","STKFLT","CHLD","CONT","STOP","TSTP","TTIN","TTOU","URG","XCPU","XFSZ","VTALRM","PROF","WINCH","IO","PWR","UNUSED","ZERR","DEBUG",(char *)NULL};
	int i;
	char temp_buffer[MAX_INPUT_BUFFER];

	if(sig<0)
		sig=-sig;

	for(i=0;sigs[i]!=(char *)NULL;i++);

	sig%=i;

	/* we received a SIGHUP, so restart... */
	if(sig==SIGHUP){

		sigrestart=TRUE;

		syslog(LOG_NOTICE,"Caught SIGHUP - restarting...\n");
	        }

	/* else begin shutting down... */
	if(sig==SIGTERM){

		/* if shutdown is already true, we're in a signal trap loop! */
		if(sigshutdown==TRUE)
			exit(STATE_CRITICAL);

		sigshutdown=TRUE;

		syslog(LOG_NOTICE,"Caught SIG%s - shutting down...\n",sigs[sig]);
	        }

	return;
        }

