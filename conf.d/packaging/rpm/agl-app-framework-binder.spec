#
# spec file for package app-framework-binder
#

%define _prefix /opt/AGL
%define __cmake cmake

Name:           agl-app-framework-binder
# WARNING {name} is not used for tar file name in source nor for setup
#         Check hard coded values required to match git directory naming
Version:        2.0
Release:        0
License:        Apache-2.0
Summary:        AGL app-framework-binder
Group:          Development/Libraries/C and C++
Url:            https://gerrit.automotivelinux.org/gerrit/#/admin/projects/src/app-framework-binder
Source:         app-framework-binder-%{version}.tar.gz
#BuildRequires:  gdb
BuildRequires:  pkgconfig(libmicrohttpd) >= 0.9.62
BuildRequires:  make
BuildRequires:  cmake
BuildRequires:  pkgconfig(libsystemd) >= 222
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(uuid)
BuildRequires:  libgcrypt-devel
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(json-c)
BuildRequires:  file-devel
BuildRequires:  gcc-c++

Requires:       libmicrohttpd >= 0.9.62

BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
Provides a test agl binder service which can be used to test agl bindings on Linux PC
This service is evolving permanently and is only designed as a helper for developper.

%package devel
Group:          Development/Libraries/C and C++
Requires:       %{name} = %{version}
Provides:       pkgconfig(%{name}) = %{version}
Summary:        AGL app-framework-binder-devel
%description devel
Provides a test agl binder service which can be used to test agl bindings on Linux PC
This service is evolving permanently and is only designed as a helper for developper.


%prep
%setup -q -n app-framework-binder-%{version}

%build
export PKG_CONFIG_PATH=%{_libdir}/pkgconfig
%cmake  -DAGL_DEVEL=1 -DINCLUDE_MONITORING=ON
%__make %{?_smp_mflags}


%install
[ -d build ] && cd build
%make_install

mkdir -p %{buildroot}%{_sysconfdir}/profile.d
cat << EOF > %{buildroot}%{_sysconfdir}/profile.d/AGL-%{name}.sh
#----------  AGL %%{name} options Start ---------"
# Object: AGL cmake option for  binder/bindings
export LD_LIBRARY_PATH=%{_libdir}:\${LD_LIBRARY_PATH}
export LIBRARY_PATH=%{_libdir}:\${LIBRARY_PATH}
export PKG_CONFIG_PATH=%{_libdir}/pkgconfig:\${PKG_CONFIG_PATH}
export PATH=%{_bindir}:\$PATH
#----------  AGL options End ---------
EOF

%post

%postun

%files
%defattr(-,root,root)
%dir %{_bindir}
%{_bindir}/afb-client-demo
%{_bindir}/afb-daemon
%{_bindir}/afb-genskel
%{_bindir}/afb-exprefs
%{_bindir}/afb-json2c

%dir %{_libdir}
%dir %{_libdir}/afb
%{_libdir}/libafbwsc.so.1
%{_libdir}/libafbwsc.so.1.1

#app-framework-binder demo
%{_libdir}/afb/*.so
%config(noreplace) %{_sysconfdir}/profile.d/AGL-%{name}.sh

#app-framework-binder monitoring
%dir %{_libdir}/afb/monitoring
%{_libdir}/afb/monitoring/*

%files devel
%defattr(-,root,root)
%dir %{_prefix}
%{_libdir}/libafbwsc.so
%dir %{_includedir}
%dir %{_includedir}/afb
%{_includedir}/afb/*
%dir %{_libdir}/pkgconfig
%{_libdir}/pkgconfig/*.pc

%changelog
* Wed Sep 27 2017 Dominig
- move to git repo
* Tue Aug 01 2017 Ronan
- initial creation
