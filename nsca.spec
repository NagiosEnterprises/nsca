%define name nsca
%define version 2.9.1
%define release 1
%define nsusr nagios
%define nsgrp nagios
%define nsport 5667
# %define nsport 8086

# Reserve option to override port setting with:
# rpm -ba|--rebuild --define 'nsport 5666'
%{?port:%define nsport %{port}}

# Macro that print mesages to syslog at package (un)install time
%define nnmmsg logger -t %{name}/rpm

Summary: Host/service/network monitoring agent for Nagios
URL: http://www.nagios.org
Name: %{name}
Version: %{version}
Release: %{release}
License: GPL
Group: Application/System
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-buildroot
Requires: bash, nagios, libmcrypt, xinetd

# uncomment this for RedHat Enterprise Linux 3:
#PreReq: util-linux, sh-utils, shadow-utils, sed, fileutils, mktemp
# SuSE Linux Enterprise Server 8:
PreReq: util-linux, sh-utils, shadow, sed, fileutils, mktemp 


%description
This program is designed to accept passive service check results from 
clients that use the send_nsca utility and pass them along to the 
Nagios process by using the external command 
interface. The program can either be run as a standalone daemon or as 
a service under inetd. If you have libmcrypt installed on your systems, 
you can choose from multiple crypto algorithms (DES, 3DES, CAST, xTEA, 
Twofish, LOKI97, RJINDAEL, SERPENT, GOST, SAFER/SAFER+, etc.) for 
encrypting the traffic between the client and the server. 
Encryption is important in this addon, as it prevents unauthorized users 
from sending bogus check results to Nagios. Read the included SECURITY 
document for more information. 

This package provides the core agent running on the Nagios server

%package send
Requires: libmcrypt
Group: Application/System
Summary: Provides the send_nsca utility running on the Nagios-Client.

%description send
This program is designed to accept passive service check results from 
clients that use the send_nsca utility (which is included in this package) 
and pass them along to the Nagios process by using the external command 
interface. The program can either be run as a standalone daemon or as 
a service under inetd. If you have libmcrypt installed on your systems, 
you can choose from multiple crypto algorithms (DES, 3DES, CAST, xTEA, 
Twofish, LOKI97, RJINDAEL, SERPENT, GOST, SAFER/SAFER+, etc.) for 
encrypting the traffic between the client and the server. 
Encryption is important in this addon, as it prevents unauthorized users 
from sending bogus check results to Nagios. Read the included SECURITY 
document for more information. 

This package provides the send_nsca utility running on the client.

%prep
%setup -q


%pre
# Create `nagios' user on the system if necessary
if id %{nsusr} 
then
	: # user already exists
else
        grep nagios /etc/group &>/dev/null || /usr/sbin/groupadd -r nagios 

	/usr/sbin/useradd -r -d /var/log/nagios -s /bin/sh -c "%{nsusr}" -g %{nsgrp} %{nsusr} || \
		%nnmmsg Unexpected error adding user "%{nsusr}". Aborting install process.
fi

# if LSB standard /etc/init.d does not exist,
# create it as a symlink to the first match we find
if [ -d /etc/init.d -o -L /etc/init.d ]; then
  : # we're done
elif [ -d /etc/rc.d/init.d ]; then
  ln -s /etc/rc.d/init.d /etc/init.d
elif [ -d /usr/local/etc/rc.d ]; then
  ln -s  /usr/local/etc/rc.d /etc/init.d
elif [ -d /sbin/init.d ]; then
  ln -s /sbin/init.d /etc/init.d
fi

%postun
/etc/init.d/xinetd restart 

%post
/etc/init.d/xinetd restart 


%build
export PATH=$PATH:/usr/sbin
CFLAGS="$RPM_OPT_FLAGS" CXXFLAGS="$RPM_OPT_FLAGS" \
./configure \
	--with-nsca-port=%{nsport} \
	--with-nsca-user=%{nsusr} \
	--with-nsca-grp=%{nsgrp} \
	--prefix=""        \
	--bindir=%{_prefix}/bin \
 	--sysconfdir=/etc/nagios \
	--localstatedir=/var/spool/nagios \


make all

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
install -b -D -m 0644 sample-config/nsca.cfg ${RPM_BUILD_ROOT}/etc/nagios/nsca.cfg
install -b -D -m 0644 sample-config/send_nsca.cfg ${RPM_BUILD_ROOT}/etc/nagios/send_nsca.cfg
install -b -D -m 0644 sample-config/nsca.xinetd ${RPM_BUILD_ROOT}/etc/xined.d/nsca
install -b -D -m 0755 src/nsca ${RPM_BUILD_ROOT}/usr/sbin/nsca
install -b -D -m 0755 src/send_nsca ${RPM_BUILD_ROOT}/usr/bin/send_nsca

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(755,root,root)
/etc/xined.d/nsca
/usr/sbin/nsca
%dir /etc/nagios
%defattr(644,root,root)
%config(noreplace) /etc/nagios/*.cfg
%defattr(755,%{nsusr},%{nsgrp})
%doc Changelog LEGAL README SECURITY

%files send
%defattr(755,root,root)
/usr/bin/send_nsca
%defattr(644,root,root)
%config(noreplace) /etc/nagios/send_nsca.cfg
%defattr(755,%{nsusr},%{nsgrp})
%doc Changelog LEGAL README SECURITY

%changelog
* Wed Jan 28 2004 Falk Höppner <fh at honix de>
- Create SPEC from nrpe.spec  
- Tested on ia32/ia64 with SLES8/RHEL3

