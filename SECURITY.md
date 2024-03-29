NSCA SECURITY README
====================


General Security Considerations
-------------------------------
Before you proceed with installing the NSCA daemon daemon on your
monitoring server, there are some security implications that you
should be aware of.

The main thing you need to be aware of is the fact that malicious
users could potentially use the NSCA client to send fake service
and host check results to the NSCA daemon (and thus Nagios).  This
is bad for two reasons:

1) Nagios could get fake check results and start generating
   notifications (which would annoy you) or host/service
   problems (like security alerts) could be cleared by the remote
   user.

2) Worse, since Nagios can be configured to run event handlers
   for hosts and services, a remote user could indirectly cause
   Nagios to shut down or restart a service (or do something
   more serious).

Running the NSCA daemon under inetd and making use of TCP wrappers
allows you to perform some host-based authentication of clients.
That isn't really good enough, as any user on a blessed client
machine could use the client to send fake check results to the
daemon (and thus to Nagios).

So what's the solution?  Encryption.



Encrypting Communications
-------------------------
In order to avoid some of the security hassles associated with
allowing remote clients to provide Nagios with host and service
check results, we can encrypt the data being sent from the client
to the NSCA daemon.

While encryption is good because it provides some privacy
as to the information that is being sent from the client to
the daemon, the main purpose of the encryption is to provide
the daemon with a way of authenticating the client and
seeing if they're authorized to provide check results.

Basically the daemon says:

   "Hey, if you (the client) used the same password and
    algorithm to encrypt the data as I use to decrypt it,
    I'll accept the check results you're providing me..."



How The Authentication Works
----------------------------
Authentication of checks results works as follows:

1) The user starts the NSCA client and passes the host and/or
   service check results to it.  A password that is used to
   encrypt the data being sent to the NSCA daemon is stored in
   the send_nsca config file on the client machine.

2) The NSCA client stuff the check results into a packet (or
   several packets if you send multiple results).

3) The NSCA client computes the CRC-32 value of the packet
   its about to send off and stores that value in the packet
   body.

4) The entire packet body (including the service checking
   information, as well as the CRC-32 value) is encrypted
   using the password stored in the send_nsca.cfg file.
   Encryption of the packet is done using the algorithm
   specified by the encryption_method variable in the
   send_nsca.cfg file.

... packet gets sent over the wire...

5) The NSCA daemon receives the packet and decrypts it using
   the password stored in the nsca.cfg file.  Decryption of
   the packet is done using the algorithm specified by the
   decryption_method variable in the nsca.cfg file.

6) The daemon calculates the CRC-32 value of the decrypted
   packet to see if it matches the CRC-32 value stored in
   the packet body (this value was previously computed and
   stored by the client).

7) If the calculated CRC-32 value matches the value that is
   stored in the packet body, the service check results that
   are stored in the packet are assumed to be from an
   authorized user.  If the calculated CRC-32 value does NOT
   match the value in the packet body, the results are assumed
   to be from an unauthorized user and the packet (and the
   host or service check results contained therein) are
   discarded.



What This Means
---------------

1) If the client uses the wrong password to encrypt the
   packet, the daemon will discard it, as the CRC-32 value
   stored in the packet will not match the computed value
   once the packet it decrypted.

2) If the client uses the wrong encryption method, the
   daemon will discard the results, as the CRC-32 value
   stored in the packet will not match the computed value
   once the packet is decrypted.

3) If someone tries to dabble with the contents of the
   packet as it is being transferred between the client and
   the server, the daemon will likely discard the packet, as
   the CRC-32 value of the packet will likely be invalid.

4) Even if someone manages to figure out a way to make
   the calculated CRC-32 value match the value stored
   in the packet, the check results stored in the packet
   that are passed along to Nagios have to match a valid
   host or service definition.  Nagios ignores all passive
   check results that come in that are not associated with
   any valid host or service definitions.



Preventing "Replay" Attacks
---------------------------

The methods described above help ensure that the data the
NSCA daemon receives is "valid" data - i.e., it was
encrypted with the appropriate passphrase and crypto
algorithm.  One problem that remains is the fact that
someone could capture the data packets being sent from the
client to the daemon and send them back to the daemon at
a later time.  This is referred to as a "replay attack".
To help prevent this, the NSCA daemon generates what is
essentially a one-time, randomly generated IV that the
client must use to encrypt data for each particular
"session".  The IV does not need to be secret, just unique.
The IV is used in conjunction with the password during
encryption and decryption.  Encrypting a packet with the
same password but different IVs results in a different
result.  Since the daemon knows what IV it generated and
sent to the client, it can verify that the data the client
sends to it has been properly encrypted.  This provides
a reasonable mechanism of preventing replay attacks.

Strict Mode
-----------

As of NSCA 2.10.1, you can now specify the `strict_mode_spoofing`
directive in nsca.cfg. This will cause the daemon to run DNS queries
for the connecting send_nsca client and for the host_name that it submits. 
If they do not have any IP addresses in common, the check result will
be discarded. Note that this will have performance implications, as
NSCA does not maintain its own DNS cache. However, if your host names
in Nagios Core match their FQDNs or IP Addresses, this can help to
prevent check spoofing.

Caveats
-------

1) These assumptions rely on the fact that you are using a
   reasonably secure encryption/decryption method in the
   NSCA clients and NSCA daemon.

2) These assumptions rely on the fact that you're using a
   reasonable secure password to encrypt/decrypt the data.
   Depending on the crypto algorithm used, this could mean
   length and/or randomness.  As a general rule, longer
   passwords or passphrases are better than shorter ones.
   Insert common sense here.

3) It is assumed that you keep tight security on the
   send_nsca.cfg and nsca.cfg config files, as they contain
   both the algorithm and password used to encrypt/decrypt
   the packets sent between the client and daemon.


Questions?
----------

If you have any questions, comments, or suggestions, feel free to contact us
via the [support forum](http://support.nagios.com/forum/) or through our
[Github page](https://github.com/NagiosEnterprises/nsca/)

