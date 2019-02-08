#!/bin/bash

ROOT=$(dirname $0)
echo ROOT=$ROOT

AFB=$ROOT/build/src/afb-daemon
CLI="$ROOT/build/src/afb-client-demo -e -s"
PORT=12345
TOKEN=knock-knock-knock

count=10
null=false
eval set -- $(getopt -o c:n -l count:,null -- "$@") || exit
while true
do
	case "$1" in
	-c|--count)
		if ! test "$2" -gt 0 2>/dev/null; then
			echo "error: $2 is not a valid count" >&2
			exit 1
		fi
		count="$2"
		shift 2
		;;
	-n|--null)
		null=true
		shift
		;;
	--)
		shift
		break
		;;
	esac
done

OUT="$ROOT/stress-out-clients"
echo rm $OUT.*
rm $OUT.* 2> /dev/null

if $null; then
	OUT=/dev/null
else
	OUT="$OUT.%03d"
fi

commands() {
cat << EOC
hello ping true
HELLO PING false
hello pIngNull true
#hello PingBug true
hello PiNgJsOn {"well":"formed","json":[1,2,3,4.5,true,false,null,"oups"]}
hello subcall {"api":"hello","verb":"pingjson","args":[{"key1":"value1"}]}
hello subcall {"api":"hello","verb":"subcall","args":{"api":"hello","verb":"pingjson","args":[{"key1":"value1"}]}}
hello subcallsync {"api":"hello","verb":"pingjson","args":[{"key1":"value1"}]}
hello subcallsync {"api":"hello","verb":"subcall","args":{"api":"hello","verb":"pingjson","args":[{"key1":"value1"}]}}
hello subcall {"api":"hello","verb":"subcallsync","args":{"api":"hello","verb":"pingjson","args":[{"key1":"value1"}]}}
hello subcallsync {"api":"hello","verb":"subcallsync","args":{"api":"hello","verb":"pingjson","args":[{"key1":"value1"}]}}
hello eventadd {"tag":"ev1","name":"event-A"}
hello eventadd {"tag":"ev2","name":"event-B"}
hello eventpush {"tag":"ev1","data":[1,2,"hello"]}
hello eventpush {"tag":"ev2","data":{"item":0}}
hello eventsub {"tag":"ev2"}
hello eventpush {"tag":"ev1","data":[1,2,"hello"]}
hello eventpush {"tag":"ev2","data":{"item":0}}
hello eventsub {"tag":"ev1"}
hello subcall {"api":"hello","verb":"eventpush","args":{"tag":"ev1","data":[1,2,"hello"]}}
hello subcall {"api":"hello","verb":"eventpush","args":{"tag":"ev2","data":{"item":0}}}
hello subcallsync {"api":"hello","verb":"eventpush","args":{"tag":"ev1","data":[1,2,"hello"]}}
hello subcallsync {"api":"hello","verb":"eventpush","args":{"tag":"ev2","data":{"item":0}}}
hello eventunsub {"tag":"ev2"}
hello eventpush {"tag":"ev1","data":[1,2,"hello"]}
hello eventpush {"tag":"ev2","data":{"item":0}}
hello eventdel {"tag":"ev1"}
hello eventpush {"tag":"ev1","data":[1,2,"hello"]}
hello eventpush {"tag":"ev2","data":{"item":0}}
hello eventdel {"tag":"ev2"}
EOC
}

r() {
	while :; do commands; done |
	$CLI "localhost:$PORT/api?token=$TOKEN" > "$1" 2>&1 &
}

echo launch clients...
i=1
while test $i -le $count; do
	echo " + launch clients $i"
	r $(printf "$OUT" $i)
	i=$(expr $i + 1)
done
echo done
wait

