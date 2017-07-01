NSCA - Nagios Service Check Acceptor
====================================

TL;DR? You can jump straight to [Compiling](#compiling) and 
[Installing](#installing).

The purpose of this addon is to allow you to send service check
results to a central monitoring server running Nagios in a secure
manner.


Explanation
-----------

There are two pieces to this addon:

1. `nsca`

   This program runs as a daemon on the central server
   that runs Nagios. It listens for host and service
   check results from remote machines (sent using the
   `send_nsca` program described below). Upon receiving
   data from a remote client, the daemon will make a
   **very** basic attempt at validating the data it has
   received from the client. This is done by decrypting
   the data with the password stored in the `nsca.cfg` 
   file. If the decrypted data looks okay (i.e. it was
   originally encrypted by the `send_ncsa` program using
   the same password), the daemon will make entries in
   the Nagios external command file telling Nagios
   to process the host or service check result.

   Notes: 

   * The nsca daemon must have sufficient rights
      to open the Nagios command file for writing.  

   * Also, Nagios will only process passive service check
      results that it finds in the external command file
      if the service has been defined in the host config
      file (i.e. `hosts.cfg`) and it is being monitored.


2. `send_nsca`

   This is the client program that is used to send
   service check information from a remote machine to
   the nsca daemon on the central machine that runs
   Nagios. Service check information is read from
   the standard input in tab-delimited format as
   follows:

       <host_name>[tab]<svc_description>[tab]<return_code>[tab]<plugin_output>[newline]

   where:

   * `<host_name>` is the short name of host that the service is associated with
   * `<svc_description>` is the description of the service
   * `<return_code>` is the numeric return code
   * `<plugin_output>` is the output from service check

   Host check information is submitted in a similiar
   fashion - just leave out the service description:

       <host_name>[tab]<return_code>[tab]<plugin_output>[newline]



Compiling
---------

The code is very basic and may not work on your particular
system without some tweaking. Most users should be able to compile
the daemon and client piece with the following commands...

    ./configure
    make all

The binaries will be located in the `src/` directory after you
run `make all` and will have to be installed manually.



Installing
----------

The `send_nsca` program and associate config file (`nsca.cfg`) should
be placed on remote machines that you want to have communicate 
with the nsca daemon. This means that you may have to compile the
`send_nsca` program on the remote machine, if its not the same
OS/architecture as that of the central server.

The `nsca` daemon and the configuration file (`nsca.cfg`) should
be placed somewhere on the central server running Nagios.

Notes:

Make sure that you specify and use the same password in
both the `nsca.cfg` and `send_nsca.cfg` files!  If you use a
different password to encrypt the data than you do to decrypt
it, the nsca daemon will reject the data you send it.



Security
--------

There are some security implications with allowing remote clients
to provide service check results to Nagios.  Because of this, you
have the option of encrypting the packets that the NSCA client sends
to the NSCA daemon. Read the [SECURITY](SECURITY.md) file for more information
on the security risks of running NSCA, along with an explanation of what
kind of protection the encryption provides you.



Running Under `inetd` or `xinetd`
-----------------------------

If you plan on running nsca under `inetd` or `xinetd` and making use
of TCP wrappers, you need to do the following things:

1. Add a line to your `/etc/services` file as follows (modify the port
   number as you see fit)

    nsca            5667/tcp  # NSCA

2. Add entries for the NSCA daemon to either your `inetd` or `xinetd`
   configuration files. Which one you use will depend on which
   superserver is installed on your system. Both methods are described
   below.

   Notes:

   If you run nsca under `inetd` or `xinetd`, the `server_port`
   and `allowed_hosts` variables in the nrpe configuration file are
   ignored.


   * `inetd`
   
     If your system uses the `inetd` superserver **WITH** tcpwrappers, add an
     entry to `/etc/inetd.conf` as follows:

         nsca   stream   tcp   nowait   <user>  /usr/sbin/tcpd  <nscabin> -c <nscacfg> --inetd

     If your system uses the `inetd` superserver **WITHOUT** tcpwrappers, add an
     entry to `/etc/inetd.conf` as follows:

         nsca   stream   tcp   nowait   <user>                  <nscabin> -c <nscacfg> --inetd

      * Replace `<user>` with the name of the user that nsca server should run as (example: `nagios`).
      * Replace `<nscabin>` with the path to the nsca binary on your system (example: `/usr/local/nagios/nsca`).
      * Replace `<nscacfg>` with the path to the nsca config file on your system (example: `/usr/local/nagios/nsca.cfg`).


   * `xinetd`

     If your system uses `xinetd` instead of `inetd`, you'll probably
     want to create a file called `nsca` in your `/etc/xinetd.d`
     directory that contains the following entries (a sample config
     file called `nsca.xinetd` should be created in the root folder of
     the distribution after you run the configure script):

         # default: on
         # description: NSCA
         service nsca
         {
           flags           = REUSE
           socket_type     = stream        
           wait            = no
           user            = <user>
           group           = <group>
           server          = <nscabin>
           server_args     = -c <nscacfg> --inetd
           log_on_failure  += USERID
           disable         = no
           only_from       = <ipaddress1> <ipaddress2> ...
         }


      * Replace `<user>` with the name of the user that the nsca server should run as (example: `nagios`).
      * Replace `<group>` with the name of the group that the nsca server should run as (example: `nagios`).
      * Replace `<nscabin>` with the path to the nsca binary on your system (example: `/usr/local/nagios/nsca`).
      * Replace `<nscacfg>` with the path to the nsca config file on your system (example: `/usr/local/nagios/nsca.cfg`).
      * Replace the `<ipaddress>` fields with the IP addresses of hosts which
        are allowed to connect to the NSCA daemon.  This only works if `xinetd` was
        compiled with support for tcpwrappers.

3. Restart `inetd` or `xinetd`. You know your system best, but some examples are:

       service inetd restart
       service xinetd restart

       systemctl restart inetd.service
       systemctl restart xinetd.service

4. Add entries to your `/etc/hosts.allow` and `/etc/hosts.deny`
   files to enable TCP wrapper protection for the nsca service.
   Alternatively, you can adjust your firewall settings as needed.
   This is an optional step, **although highly recommended**.

Changes
-------

Changes can be seen at the [CHANGELOG](CHANGELOG.md) file.


Contributors
------------

See the file at [CONTRIBUTORS](CONTRIBUTORS.md) for a full list of authors,
contributors, and maintainers.

Current Version
---------------

The current version of this program can be found at:

  https://github.com/NagiosEnterprises/nsca/

Other open-source Nagios software can be found at:

  https://github.com/NagiosEnterprises/

License Notice
--------------

This software is released under GPLv2. See the full license at the 
[LICENSE](LICENSE.md) file.

Questions?
----------

If you have any questions, comments, or suggestions, feel free to contact us
via the [support forum](http://support.nagios.com/forum/) or through our
[Github page](https://github.com/NagiosEnterprises/nsca/).

