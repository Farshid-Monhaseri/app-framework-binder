#!/bin/bash

export R=$(realpath $(dirname $0)/..)
export PATH="$R/bin:$R/scripts:$PATH"

cd $R/bin

lcov -c -i -d $R/bin -o $R/lcov-out.info

vg() {
	if [[ -z "$NOVALGRIND" ]]; then
		valgrind "$@"
	else
		while :; do
			case "$1" in
			--*) shift;;
			*) break;;
			esac
		done
		"$@"
	fi
}

mk() {
	echo
	echo "*******************************************************************"
	echo "** $*"
	echo "*******************************************************************"
	lcov -c -i -d $R/bin -o $R/fake.info
	"$@"
	lcov -c -d $R/bin -o $R/tmp.info
	mv $R/lcov-out.info $R/previous.info
	lcov -a $R/tmp.info -a $R/previous.info -o $R/lcov-out.info
	rm $R/previous.info $R/fake.info  $R/tmp.info
}

mkdir /tmp/ldpaths
export AFB_LDPATHS=/tmp/ldpaths
export AFB_TRACEAPI=no

##########################################################
# test to check options
##########################################################
mk $R/bin/afb-daemon-cov --help

mk $R/bin/afb-daemon-cov --version

mk $R/bin/afb-daemon-cov --no-httpd --fake-option

mk $R/bin/afb-daemon-cov --daemon --session-max

mk $R/bin/afb-daemon-cov --ws-client fake --session-max toto

mk $R/bin/afb-daemon-cov --foreground --port -55

mk $R/bin/afb-daemon-cov --foreground --port 9999999

mk $R/bin/afb-daemon-cov --no-ldpath --traceapi fake

mk $R/bin/afb-daemon-cov --traceditf all --tracesvc all --log error,alarm

mk $R/bin/afb-daemon-cov --call noapi/noverb:false

mk $R/bin/afb-daemon-cov --call not-a-call

LISTEN_FDNAMES=toto,demat LISTEN_FDS=5
typeset -x LISTEN_FDNAMES LISTEN_FDS
mk $R/bin/afb-daemon-cov --no-ldpath --binding $R/bin/demat.so --ws-server sd:demat --call "demat/exit:0"
typeset +x LISTEN_FDNAMES LISTEN_FDS

mk $R/bin/afb-daemon-cov --weak-ldpaths $R/ldpath/weak --binding $R/bin/demat.so --ws-server sd:demat --call "demat/exit:0"

AFB_DEBUG_BREAK=zero,one,two,main-start  AFB_DEBUG_WAIT="here I am"
typeset -x AFB_DEBUG_BREAK AFB_DEBUG_WAIT
mk $R/bin/afb-daemon-cov --rootdir $R/i-will-never-exist
typeset +x AFB_DEBUG_BREAK AFB_DEBUG_WAIT

mk $R/bin/afb-daemon-cov --workdir=/etc/you/should/not/be/able/to/create/me

mk $R/bin/afb-daemon-cov --exec $R/it-doesn-t-exist

##########################################################
# test of the bench
##########################################################
mk $R/bin/test-apiset

mk $R/bin/test-session

mk $R/bin/test-wrap-json

##########################################################
# true life test
##########################################################
mk \
vg \
	--log-file=$R/valgrind.out \
	--trace-children=no \
	--track-fds=yes \
	--leak-check=full \
	--show-leak-kinds=all \
	--num-callers=50 \
$R/bin/afb-daemon-cov \
	--verbose \
	--verbose \
	--verbose \
	--verbose \
	--quiet \
	--quiet \
	--quiet \
	--quiet \
	--quiet \
	--quiet \
	--log error,warning,notice,info,debug,critical,alert-error,warning,notice,info,debug,critical,alert+error,warning,notice,info,debug,critical,alert \
	--foreground \
	--name binder-cov \
	--port 8888 \
	--roothttp $R/www \
	--rootbase /opa \
	--rootapi /api \
	--alias /icons:$R/www \
	--apitimeout 90 \
	--cntxtimeout 3600 \
	--cache-eol 200 \
	--workdir . \
	--uploaddir . \
	--rootdir . \
	--ldpaths $R/ldpath/strong \
	--binding $R/bin/demat.so \
	--auto-api $R/apis/auto \
	--token HELLO \
	--random-token \
	--session-max 1000 \
	--tracereq all \
	--traceapi all \
	--traceses all \
	--traceevt all \
	--traceglob none \
	--monitoring \
	--set hello/key:a-kind-of-text \
	--call demat/ping:true \
	--call hello/ping:false \
	--ws-server unix:$R/apis/ws/hello \
	--ws-server unix:$R/apis/ws/salut \
	--exec $R/scripts/run-parts.sh @p @t

##########################################################
# true life test
##########################################################
mk \
vg \
	--log-file=$R/valgrind.out \
	--trace-children=no \
	--track-fds=yes \
	--leak-check=full \
	--show-leak-kinds=all \
	--num-callers=50 \
$R/bin/afb-daemon-cov \
	--quiet \
	--quiet \
	--foreground \
	--roothttp $R/www \
	--alias /icons:$R/www \
	--workdir . \
	--uploaddir . \
	--rootdir . \
	--ldpaths $R/ldpath/strong \
	--binding $R/bin/demat.so \
	--auto-api $R/apis/auto \
	--random-token \
	--ws-server unix:$R/apis/ws/hello \
	--ws-server unix:$R/apis/ws/salut \
	--ws-server localhost:9595/salut \
	--exec \
            afb-daemon \
		--auto-api $R/apis/auto \
		--auto-api $R/apis/ws \
		--ws-client localhost:@p/salut2 \
		$R/scripts/run-parts.sh @@p @@t

exit 0


