# $Id$
Name: pktstat
Version: 1.7.4
Source0: http://www.adaptive-enterprises.com.au/~d/software/pktstat/%{name}-%{version}.tar.gz
Release: 1
Summary: Real-time packet viewer
Group: Applications
License: BSD
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
make PREFIX=%{_prefix}

%install
mkdir -p %{buildroot}/%{_bindir}
mkdir -p %{buildroot}/%{_mandir}/man1
make install BINDIR=%{buildroot}%{_bindir} \
	     MANDIR=%{buildroot}%{_mandir}/man
chmod u+w %{buildroot}%{_bindir}/*
chmod u+w %{buildroot}%{_mandir}/man1/*

%files
%attr(0755,root,root) %{_bindir}/pktstat
%attr(0644,root,root) %{_mandir}/man1/pktstat.0*

