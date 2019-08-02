# AGL Framework Binder

This project provides the binder component of the the microservice architecture 
of Automotive Grade Linux (AGL).

This project is available there https://git.automotivelinux.org/src/app-framework-binder/

It can be cloned with **git clone https://git.automotivelinux.org/src/app-framework-binder**.


## License and copying

This software is an open source software funded by LinuxFoundation and Renesas.

This software is delivered under the terms of the open source license Apache 2.

This license is available in the file LICENSE-2.0.txt or on the worl wide web at the
location https://opensource.org/licenses/Apache-2.0


## Building

### Requirements

Building the AGL framework binder has been tested under 
  **Ubuntu**, **Debian** and **Fedora 26** with gcc 6 and 7.

It requires the following libraries:

 * libmagic ("libmagic-dev" under Ubuntu, "file-devel" under Fedora);
 * libmicrohttpd >= 0.9.60  (fetch and build from "http://ftp.gnu.org/gnu/libmicrohttpd");
 * json-c ("libjson-c-dev/devel");
 * uuid ("uuid-dev/libuuid-devel");
 * openssl ("libssl-dev/openssl-devel");
 * systemd >= 222 ("libsystemd-dev/systemd-devel");

The following library can be used for checking permissions:

 * cynara (https://github.com/Samsung/cynara)

and the following tools:

 * gcc;
 * pkg-config;
 * cmake >= 3.0

To install all dependencies under Ubuntu (excepting libmicrohttpd), please type:

	$ apt-get install libmagic-dev libjson-c-dev uuid-dev libsystemd-dev libssl-dev gcc make pkg-config cmake

or under Fedora (excepting libmicrohttpd and rtl-sdr):

	$ dnf install git passwd iproute openssh-server openssh-client
	$ dnf install file-devel gcc gdb make pkgconfig cmake
	$ dnf install json-c-devel libuuid-devel systemd-devel openssl-devel

### Simple compilation

The following commands will install the binder in your subdirectory
**$HOME/local** (instead of **/usr/local** the default when 
*CMAKE_INSTALL_PREFIX* isn't set).

	$ git clone https://git.automotivelinux.org/src/app-framework-binder
	$ cd app-framework-binder
	$ mkdir build
	$ cd build
	$ cmake -DCMAKE_INSTALL_PREFIX=$HOME/local ..
	$ make install

### Advanced compilation

You can tune options when calling cmake. Here are the known options with
their default values.

	$ git clone https://git.automotivelinux.org/src/app-framework-binder
	$ cd app-framework-binder
	$ mkdir build
	$ cd build
	$ cmake \
	      -DCMAKE_INSTALL_PREFIX=/usr/local  \
	      -DAGL_DEVEL=OFF                    \
	      -DINCLUDE_MONITORING=OFF           \
	      -DINCLUDE_SUPERVISOR=OFF           \
	      -DINCLUDE_DBUS_TRANSPARENCY=OFF    \
	      -DINCLUDE_LEGACY_BINDING_V1=OFF    \
	      -DINCLUDE_LEGACY_BINDING_VDYN=OFF  \
	      -DAFS_SUPERVISOR_PORT=1619         \
	      -DAFS_SUPERVISOR_TOKEN="HELLO"     \
	      -DAFS_SUPERVISION_SOCKET="@urn:AGL:afs:supervision:socket" \
	      -DUNITDIR_SYSTEM=${CMAKE_INSTALL_LIBDIR}/systemd/system    \
	    ..
	$ make install

The configuration options are:

| Variable                    | Type    | Feature
|:----------------------------|:-------:|:------------------------------
| AGL_DEVEL                   | BOOLEAN | Activates development features
| INCLUDE_MONITORING          | BOOLEAN | Activates installation of monitoring
| INCLUDE_SUPERVISOR          | BOOLEAN | Activates installation of supervisor
| INCLUDE_DBUS_TRANSPARENCY   | BOOLEAN | Allows API transparency over DBUS
| INCLUDE_LEGACY_BINDING_V1   | BOOLEAN | Includes the legacy Binding API version 1
| INCLUDE_LEGACY_BINDING_VDYN | BOOLEAN | Includes the legacy Binding API version dynamic
| AFS_SUPERVISOR_PORT         | INTEGER | Port of service for the supervisor
| AFS_SUPERVISOR_TOKEN        | STRING  | Secret token for the supervisor
| AFS_SUPERVISION_SOCKET      | STRING  | Internal socket path for supervision (internal if starts with @)
| UNITDIR_SYSTEM              | STRING  | Path to systemd system unit files for installing supervisor




***** TO BE COMPLETED *****












## Simple demo




### Testing/Debug

```
$ ${AFB_DAEMON_DIR}/build/src/afb-daemon --help
$ ${AFB_DAEMON_DIR}/build/src/afb-daemon --port=1234 --token='' --ldpaths=${AFB_DAEMON_DIR}/build --sessiondir=/tmp --rootdir=${AFB_DAEMON_DIR}/test
```

### Starting

```
$ afb-daemon --help
$ afb-daemon --verbose --port=<port> --token='' --sessiondir=<working directory> --rootdir=<web directory (index.html)>
```

### Example

```
$ afb-daemon --verbose --port=1234 --token='' --sessiondir=/tmp --rootdir=/srv/www/htdocs --alias=icons:/usr/share/icons
```

### Directories & Paths

Default behaviour is to locate ROOTDIR in $HOME/.AFB

### REST API

Developers are intended to provide a structure containing : API name, corresponding methods/callbacks, and optionally a context and a handle.
A handle is a void* structure automatically passed to API callbacks.
Callbacks also receive HTTP GET data as well as HTTP POST data, in case a POST method was used.
Every method should return a JSON object or NULL in case of error.

API plugins can be protected from timeout and other errors. By default this behaviour is deactivated, use --apitimeout to activate it.

        STATIC AFB_restapi myApis[]= {
          {"ping"    , AFB_SESSION_NONE,  (AFB_apiCB)ping,     "Ping Function"},
          {"action1" , AFB_SESSION_CHECK, (AFB_apiCB)action1 , "Action-1"},
          {"action2" , AFB_SESSION_CHECK, (AFB_apiCB)action2 , "Action-2"},
          {NULL}
        };

        PUBLIC AFB_plugin *pluginRegister () {
            AFB_plugin *plugin = malloc (sizeof (AFB_plugin));
            plugin->type  = AFB_PLUGIN_JSON;
            plugin->info  = "Plugin Sample";
            plugin->prefix= "myPlugin";
            plugin->apis  = myApis;
            return (plugin);
        }

### HTML5 and AngularJS Redirects

Binder supports HTML5 redirect mode even with an application baseurl.
Default value for application base URL is /opa.
See Application Framework HTML5 Client template at https://github.com/iotbzh/afb-client-sample

If the Binder receives something like _http://myopa/sample_ when sample is not the homepage of the AngularJS OPA,
it will redirect to _http://myopa/#!sample_.
This redirect will return the _index.html_ OPA file and will notify AngularJS not to display the homepage, but the sample page.

Warning: in order for AngularJS applications to be able to work with both BASEURL="/" and BASEURL="/MyApp/", all page references have to be relative.

Recommended model is to develop with a BASEURL="/opa" as any application working with a BASEURL will work without, while the opposite is not true.

Note: If a resource is not accessible from ROOTDIR then the "--alias" switch should be used, as in: --alias=/icons:/usr/share/icons.
Only use alias for external support static files. This should not be used for API and OPA.


### Ongoing work

Javascript plugins. As of today, only C plugins are supported, but JS plugins are on the TODO list.
