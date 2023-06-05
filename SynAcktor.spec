%define _unpackaged_files_terminate_build 0

Name: SynAcktor
Version: %{_version}
Release: %{_release}
Summary: SynAcktor
License: Arista Networks
Group: EOS/Extension
Source0: %{name}-%{version}-%{release}.%{buildarch}.tar.gz
Packager: Eric Tedor <et@arista.com>
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: Eos-release >= 3:4.24.0

%description
An Arista EOS extension that monitors TCP service availability.

%pre

%prep
%setup -q -n %{name}

%build

%install
rm -rf %{buildroot}
%{__mkdir} -p %{buildroot}/tmp
%{__install} %{_builddir}/%{name}/SynAcktor.py %{buildroot}/tmp/SynAcktor.py
%{__install} %{_builddir}/%{name}/synscan.py %{buildroot}/tmp/synscan.py

%post
bindir="/usr/local/bin"
mv /tmp/SynAcktor.py "${bindir}/SynAcktor"
mv /tmp/synscan.py "${bindir}/synscan.py"

%preun

%files
%attr(0755, root, root) /tmp/SynAcktor.py
%attr(0755, root, root) /tmp/synscan.py
