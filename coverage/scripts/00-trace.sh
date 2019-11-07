#!/bin/sh

$R/bin/afb-client -s -k $WSURL <<EOC &
monitor trace {"add":{"tag":"fun","api":"*","request":"*","event":"*","session":"*","global":"*"}}
monitor trace {"add":{"tag":"T","api":"!(monitor)","request":"*","event":"*","session":"*","global":"*"}}
monitor trace {"add":{"tag":"T","api":"monitor","request":"none"}}
monitor trace {"drop":{"tag":"fun"}}
EOC
