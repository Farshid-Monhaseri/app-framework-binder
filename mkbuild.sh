#/bin/sh

h="$(dirname $0)"

mkdir -p "$h/build" || exit
cd "$h/build" || exit

[ "$1" = "-f" ] && { rm -r * 2>/dev/null; shift; }
[ "$1" = "--force" ] && { rm -r * 2>/dev/null; shift; }

cmake \
	-DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_INSTALL_PREFIX=~/.local \
	-DAGL_DEVEL=ON \
	-DWITH_SUPERVISOR=ON \
	-DWITH_DBUS_TRANSPARENCY=ON \
	-DWITH_LEGACY_BINDING_V1=ON \
	-DWITH_LEGACY_BINDING_V2=ON \
	-DWITH_LEGACY_BINDING_VDYN=ON \
	-DWITH_DYNAMIC_BINDING=ON \
	-DWITH_SIG_MONITOR_DUMPSTACK=ON \
	-DWITH_SIG_MONITOR_SIGNALS=ON \
	-DWITH_SIG_MONITOR_FOR_CALL=ON \
	-DWITH_SIG_MONITOR_TIMERS=ON \
	-DWITH_AFB_HOOK=ON \
	-DWITH_AFB_TRACE=ON \
	-DINCLUDE_MONITORING=ON \
	-DINCLUDE_SUPERVISOR=ON \
	-DINCLUDE_DBUS_TRANSPARENCY=ON \
	-DINCLUDE_LEGACY_BINDING_V1=ON \
	-DINCLUDE_LEGACY_BINDING_VDYN=ON \
	..

make -j "$@"

