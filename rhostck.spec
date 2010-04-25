#
# spec file for package rhostck (Version 0.5)
#
# Copyright  (c)  2010  Bernhard Graf <graf@movingtarget.de>
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

%define name rhostck
%define version 0.5
%define release 0
%define group Utilities/System

%define build_dietlibc	0

%define is_mandrake	%([ -e /etc/mandrake-release ]; echo $[1-$?])
%define is_mandriva	%([ -e /etc/mandriva-release ]; echo $[1-$?])
%define is_suse		%([ -e /etc/SuSE-release ]; echo $[1-$?])
%define is_redhat	%([ -e /etc/redhat-release ]; echo $[1-$?])
%define is_fedora	%([ -e /etc/fedora-release ]; echo $[1-$?])

%if %is_fedora
%define distribution %(head -n1 /etc/fedora-release)
%endif
%if %is_redhat
%define distribution %(head -n1 /etc/redhat-release)
%endif
%if %is_suse
%define distribution %(head -n1 /etc/SuSE-release)
%define group Productivity/Networking/Email/Servers
%endif
%if %is_mandriva
%define release %{release}mdv
%define distribution %(head -n1 /etc/mandriva-release)
%define group Networking/Mail
%endif
%if %is_mandrake
%define release %{release}mdk
%define distribution %(head -n1 /etc/mandrake-release)
%define group Networking/Mail
%endif

# commandline overrides:
# rpm -ba|--rebuild --with dietlibc
%{?_with_dietlibc: %{expand: %%define build_dietlibc 1}}

Name:		%{name}
Version:	%{version}
Release:	%{release}
Distribution:   %{distribution}
Group:		%{group}
Summary:	Anti-SPAM companion for rblsmtpd
License:	MIT
Source:		%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%(id -nu)
BuildRequires:	c_compiler make binutils coreutils
%if %{build_dietlibc}
BuildRequires:	dietlibc >= 0.30
%endif


%description
rhostck is a companion program for tcpserver and rblsmtpd, that sets the
RBLSMTPD environment variable with an error message for suspicious sender
hostnames. It is therefore probably most useful for a typical setup of the
qmail mail server.

rhostck works by checking the sender's hostname, and if it doesn't like it
for some reason, it will instruct rblsmtpd to close the SMTP connection
with an error message.

rhostck is not meant as a comprehensive SPAM protection, but a low-resource
pre-selector in order to cut down the number of mails, that have to be
processed in subsequent stages of the mail incoming queue.
%if %{build_dietlibc}
Built with dietlibc.
%endif
Author:
-------
    Bernhard Graf

%debug_package

%prep
%setup -n %{name}-%{version}
echo %{_exec_prefix} >conf-home
%if %{build_dietlibc}
echo diet cc $RPM_OPT_FLAGS >conf-cc
echo diet cc >conf-ld
%else
echo cc $RPM_OPT_FLAGS >conf-cc
echo cc >conf-ld
%endif

%build
%{__make}

%install
test "%{buildroot}" != "/" -a -d "%{buildroot}" && %{__rm} -rf "%{buildroot}"
%{__mkdir_p} %{buildroot}%{_exec_prefix}

echo %{buildroot}%{_exec_prefix} >conf-home
%{__rm} -f install.o auto_home.[co] install
%{__make}
./install
%{__mkdir_p} %{buildroot}%{_mandir}/man1
%{__install} -m 0644 rhostck.1 %{buildroot}%{_mandir}/man1

%clean
test "%{buildroot}" != "/" -a -d "%{buildroot}" && %{__rm} -rf "%{buildroot}"

%files
%defattr(-,root,root)
%doc CHANGES README.mkdn TODO.mkdn
%attr(0755,root,root) %{_bindir}/rhostck
%attr(0644,root,root) %{_mandir}/man1/rhostck*

%changelog
* Sun Apr 25 2010 Bernhard Graf <graf@movingtarget.de> 0.5-0
- Upgrade to 0.5
* Tue Apr 20 2010 Bernhard Graf <graf@movingtarget.de> 0.4-0
- Upgrade to 0.4
* Sun Apr 18 2010 Bernhard Graf <graf@movingtarget.de> 0.3-0
- Initial wrap
