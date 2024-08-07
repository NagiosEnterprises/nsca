NSCA Changelog
==============

2.10.3 - 2024-08-01
-------------------
 * Allow NSCA to bind to the loopback address (Imre Jonk)
 * Improved clarity of error when running in the foreground while already running in the background (Griffin Westerman)

2.10.2 - 2022-06-06
-------------------
 * Fixed exiting with STATE_OK when no packets were successfully sent
 * Added systemd service file
 * Fixed compilation warning

2.10.1 - 2021-10-27
------------------
 * Fixed backward compatibility issue with -d in send_nsca (#44)
 * Restored and fixed newline escaping, which was removed in 2.10
 * Added the strict_mode_spoofing directive. See SECURITY for details. 

2.10 - 2020-04-02
------------------
 * Changed release date to ISO format (yyyy-mm-dd) (John Frickson)
 * Add IPv6 support (Stuart D. Gathman, Miquel van Smoorenburg) 
 * Add --quiet mode to send_nsca (Timo Juhani Lindfors)
 * Add --ds to specify block delimiters (for sending multiple checks at once) in send_nsca (Nate Rini)
 * Add legacy_2_7_mode (for sending to nsca 2.7.x) to send_nsca (Adrian Freihofer, Xavier Bachelot)
 * Add foreground mode (Nate Rini)
 * Send errors to stderr, where they belong (Bas Couwenberg / Sean Finney)
 * Fix crashes on ECONNABORTED (Craig Leres)
 * Fix potential buffer overflow (Bas Couwenberg)
 * Spelling fixes (Josh Soref, Lajos Veres, Bas Couwenberg)
 * Removed escape newlines so that long output works (Bryan Heden)


2.9.2 - 2016-12-07
------------------
 * Renamed configure.in to configure.ac and added check for sigaction (John Frickson)
 * Replaced all instances of signal() with sigaction() + blocking (John Frickson)
 * Race condition when opening command file (mvela / John Frickson)
 * Fix missing argument in open calls (Xavier Bachelot / John Frickson)
 * NSCA close/POLLNVAL/accept bug causes hang (mib / John Frickson)


2.9.1 - 01/27/2012
------------------
 * Applied patch to allow packets arriving with a future time stamp (Daniel Wittenberg)
 * Updated server (nsca) to allow packets with older, smaller packet size (Eric Stanley)


2.9 - 11/04/2011
----------------
 * Add config directive to submit directly to checkresults directory (Mike Lindsey)
 * Support multi-line check output with 4000 character limit (Mike Lindsey)


2.8 - 07/07/2009
----------------
 * Added --with-log-facility option to control syslog logging (Ryan Ordway and Brian Seklecki)
 * Fixed bug where daemon would segfault if mcrypt library was not initialized before timeout (Holger Weiss)
 * Fixed bug with switching from dump file to command file when running under single mode (Ton Voon)
 * Fix for small memory leak with running as a single process daemon (Daniel)


2.7.2 - 07/03/2007
------------------
 * Fixed bug with NSCA daemon eating CPU if child process couldn't accept a connection in multi-process mode (Chris Wilson)


2.7.1 - 01/29/2007
------------------
 * Fixed bug that prevented single mode daemon from working properly
 * Added sample scripts for testing functionality to nsca_tests/ (Ton Voon/Altinity)


2.7 - 12/13/2006
----------------
 * Fixed crash from malformed command line
 * Updated to config.sub and config.guess to latest from GNU Savannah


2.6 - 04/06/2006
----------------
 * Spec file fix
 * Segfault fix in encryption library cleanup
 * Daemon now exits with an error if it can't drop privileges
 * Added chroot support (Sean Finney)
 * Added support for writing a PID file
 * Added support for reloading config files with SIGHUP


2.5 - 01/21/2006
----------------
 * Native TCP wrapper support in daemon mode
 * Memory leak fix and cleanup (Mark Ferlatte)
 * Compiler warning fix (David Binderman)
 * max_packet_age=0 will disable packet timestamp checks
 * New config.sub and config.guess for checking local system type


2.4 - 07/23/2003
----------------
 * Better support for u_int32_t detection
 * Minor bug fixes


2.3 - 01/26/2003
----------------
 * Minor changes to daemon init code
 * Minor Makefile fixes


2.2 - 01/08/2002
----------------
 * Hopefully better support for Solaris (u_int32_t)
 * Syntax changes for command line arguments
 * Added support for passive host checks (supported only in Nagios 2.x and
later)
 * Added sample xinetd config file (nsca.xinetd)
 * Minor mods and bug fixes


2.1 - 06/10/2002
----------------
 * Fix for compiling under Solaris (Scott Cokely)
 * Added setuid/setgid option to config file


2.0 - 02/21/2002
----------------
 * Name and version change


1.2.0 - 02/12/2002
------------------
 * Compatability between older versions has been broken!
 * Server now sends client IV and timestamp, fixing
  encryption problems and making it more resistent
  to "replay" attacks (Ralf Ertzinger)
 * Random IV is now seeded from /dev/urandom instead
  of time() if possible
 * Added directions on running under xinetd to README
 * Implemented Beej's sendall() to handle incomplete send()s
 * Added single-mode daemon code (David Luyer)
 * Fixed problem with aggregated writes (David Luyer)
 * Better autoconf detection of libmcrypt (Jay McCarthy)
 * Added ability to dump check results to alternate
  dump file if command file does not exist (i.e. NetSaint
  is not running)
 * Removed some old crud


1.1.2 - 09/22/2001
------------------
 * Added append_to_file option to allow for opening the
  command file in either write or append mode
 * Explicit integer size in packet structure
 * NULL IV is used for both encryption/decryption.  This
  leaves the daemon open to "replay" attacks, but will
  disappear in future revisions when IV negotiation
  between the client and daemon is implemented.


1.1.1 - 04/26/2001
------------------
 * Configure script bug fix


1.1.0 - 02/24/2001
------------------
 * Added encryption routines (using libmcrypt)
 * Minor code enhancements/cleanups


1.0b3 - 12/21/2000
------------------
 * Removed lock file code, as 0.0.7 uses a named pipe
 * Documented aggregated_writes option


1.0b2 - 08/26/2000
------------------
 * Added option to use write lock when updating external
  command file


1.0b1 - 04/17/2000
------------------
 * Initial cut
