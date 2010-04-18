#
# spec file for package rhostck (Version 0.3)
#
# Copyright  (c)  2010  Bernhard Graf <graf@movingtarget.de>
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#

%define name rhostck
%define version 0.3
%define release 0

%define build_dietlibc	0

# commandline overrides:
# rpm -ba|--rebuild --with dietlibc
%{?_with_dietlibc: %{expand: %%define build_dietlibc 1}}

Name:		%{name}
Version:	%{version}
Release:        %{release}
Summary:	Anti-SPAM companion for rblsmtpd
License:	MIT
Group:		Productivity/Networking/Email/Servers
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%(id -nu)
BuildRequires:	c_compiler make binutils coreutils
%if %{build_dietlibc}
BuildRequires:	dietlibc >= 0.30
%endif

%description
rhostck is companion program for tcpserver and rblsmtpd, that sets the
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

%clean
test "%{buildroot}" != "/" -a -d "%{buildroot}" && %{__rm} -rf "%{buildroot}"

%files
%defattr(-,root,root)
%doc CHANGES README.mkdn TODO.mkdn
%attr(0755,root,root) %{_bindir}/rhostck

%changelog
* Sun Apr 18 2010 Bernhard Graf <graf@movingtarget.de> 0.3-0
- Initial wrap
