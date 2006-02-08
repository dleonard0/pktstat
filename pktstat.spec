# $Id$
Name: pktstat
Version: 1.8.1
Source0: http://www.adaptive-enterprises.com.au/~d/software/pktstat/%{name}-%{version}.tar.gz
Release: 1
Summary: Displays a live list of active connections and what files are being transferred.
Group: Applications/Internet
Copyright: Public Domain
License: BSD
Vendor: David Leonard
URL: http://www.adaptive-enterprises.com.au/~d/software/pktstat/
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%description
Display a real-time list of active connections seen on a network
interface, and how much bandwidth is being used by what. Partially decodes
HTTP and FTP protocols to show what filename is being transferred. X11
application names are also shown. Entries hang around on the screen for
a few seconds so you can see what just happened. Also accepts filter
expressions á la tcpdump.

%prep
%setup

%build
%configure
make

%install
make install DESTDIR="$RPM_BULID_ROOT"

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/pktstat
%attr(0644,root,root) %{_mandir}/man1/pktstat.*
%doc README
