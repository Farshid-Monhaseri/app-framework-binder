#!/bin/bash

ROOT=$(dirname $0)
cd ${ROOT:-.}
ROOT=$(pwd)
echo ROOT=$ROOT

AFB=build/src/afb-daemon
HELLO=build/bindings/samples/hello3.so
PORT=12345
TEST=test
TOKEN=knock-knock-knock

OUT=stress-out-server
rm $OUT*

tool=
ws=false
eval set -- $(getopt -o wgsv -l ws,gdb,strace,valgrind -- "$@") || exit
while true
do
	case "$1" in
	-w|--ws) ws=true; shift;;
	-g|--gdb) tool=gdb; shift;;
	-s|--strace) tool=strace; shift;;
	-v|--valgrind) tool=valgrind; shift;;
	--) shift; break;;
	esac
done

case $tool in
 gdb) cmd="$(type -p gdb) -ex run --args";;
 valgrind) cmd="$(type -p valgrind) --leak-check=full";;
 strace) cmd="$(type -p strace) -tt -f -o $OUT.strace";;
 *) cmd=;;
esac

if $ws; then
  CMD="$AFB -q --no-ldpaths --binding=$HELLO --session-max=100 --ws-server=unix:@afw/hello --no-httpd --exec $cmd $AFB --session-max=100 --port=$PORT --no-ldpaths --roothttp=$TEST --token=$TOKEN --ws-client=unix:@afw/hello "
else
  CMD="$cmd $AFB -q --session-max=100 --port=$PORT --workdir=$ROOT --roothttp=$TEST --token=$TOKEN --no-ldpaths --binding=$HELLO"
fi


echo "launch: $CMD $@"
case $tool in
 gdb) $CMD "$@";;
 *) $CMD "$@" 2>&1 | tee $OUT;
esac
wait
