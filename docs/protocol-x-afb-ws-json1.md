# The websocket protocol x-afb-ws-json1

The WebSocket protocol *x-afb-ws-json1* is used to communicate between
an application and a binder. It allows access to all registered apis
of the binder.

This protocol is inspired from the protocol **OCPP - SRPC** as described for
example here:
[OCPP transport specification - SRPC over WebSocket](http://www.gir.fr/ocppjs/ocpp_srpc_spec.shtml).

The registration to the IANA is still to be done, see:
[WebSocket Protocol Registries](https://www.iana.org/assignments/websocket/websocket.xml)

This document gives a short description of the protocol *x-afb-ws-json1*.
A more formal description has to be done.

## Architecture

The protocol is intended to be symmetric. It allows:

- to CALL a remote procedure that returns a result
- to push and receive EVENT

## Messages

Valid messages are made of *text* frames that are all valid JSON.

Valid messages are:

Calls:

```txt
[ 2, ID, PROCN, ARGS ]
[ 2, ID, PROCN, ARGS, TOKEN ]
```

Replies (3: OK, 4: ERROR):

```txt
[ 3, ID, RESP ]
[ 4, ID, RESP ]
```

Events:

```txt
[ 5, EVTN, OBJ ]
```

Where:

| Field | Type   | Description
|-------|--------|------------------
| ID    | string | A string that identifies the call. A reply to that call use the ID of the CALL.
| PROCN | string | The procedure name to call of the form "api/verb"
| ARGS  | any    | Any argument to pass to the call (see afb_req_json that returns it)
| RESP  | any    | The response to the call
| TOKEN | string | The authorisation token
| EVTN  | string | Name of the event in the form "api/event"
| OBJ   | any    | The companion object of the event

Below, an example of exchange:

```txt
C->S:   [2,"156","hello/ping",null]
S->C:   [3,"156",{"response":"Some String","jtype":"afb-reply","request":{"status":"success","info":"Ping Binder Daemon tag=pingSample count=1 query=\"null\"","uuid":"ec30120c-6997-4529-9d63-c0de0cce56c0"}}]
```

## History

### 14 November 2019

Removal of token returning. The replies

```txt
[ 3, ID, RESP, TOKEN ]
[ 4, ID, RESP, TOKEN ]
```

are removed from the specification.

## Future

Here are the planned extensions:

- add binary messages with cbor data
- add calls with unstructured replies

This could be implemented by extending the current protocol or by
allowing the binder to accept either protocol including the new ones.

## Javascript implementation

The file **AFB.js** is a javascript implementation of the protocol.

Here is that code:

```javascript
/*
 * Copyright (C) 2017-2019 "IoT.bzh"
 * Author: Jos?? Bollo <jose.bollo@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
AFB = function(base, initialtoken){

if (typeof base != "object")
   base = { base: base, token: initialtoken };

var initial = {
   base: base.base || "api",
   token: base.token || initialtoken || "HELLO",
   host: base.host || window.location.host,
   url: base.url || undefined
};

var urlws = initial.url || "ws://"+initial.host+"/"+initial.base;

/*********************************************/
/****                                     ****/
/****             AFB_context             ****/
/****                                     ****/
/*********************************************/
var AFB_context;
{
   var UUID = undefined;
   var TOKEN = initial.token;

   var context = function(token, uuid) {
      this.token = token;
      this.uuid = uuid;
   }

   context.prototype = {
      get token() {return TOKEN;},
      set token(tok) {if(tok) TOKEN=tok;},
      get uuid() {return UUID;},
      set uuid(id) {if(id) UUID=id;}
   };

   AFB_context = new context();
}
/*********************************************/
/****                                     ****/
/****             AFB_websocket           ****/
/****                                     ****/
/*********************************************/
var AFB_websocket;
{
   var CALL = 2;
   var RETOK = 3;
   var RETERR = 4;
   var EVENT = 5;

   var PROTO1 = "x-afb-ws-json1";

   AFB_websocket = function(on_open, on_abort) {
      var u = urlws;
      if (AFB_context.token) {
         u = u + '?x-afb-token=' + AFB_context.token;
         if (AFB_context.uuid)
            u = u + '&x-afb-uuid=' + AFB_context.uuid;
      }
      this.ws = new WebSocket(u, [ PROTO1 ]);
      this.url = u;
      this.pendings = {};
      this.awaitens = {};
      this.counter = 0;
      this.ws.onopen = onopen.bind(this);
      this.ws.onerror = onerror.bind(this);
      this.ws.onclose = onclose.bind(this);
      this.ws.onmessage = onmessage.bind(this);
      this.onopen = on_open;
      this.onabort = on_abort;
   }

   function onerror(event) {
      var f = this.onabort;
      if (f) {
         delete this.onopen;
         delete this.onabort;
         f && f(this);
      }
      this.onerror && this.onerror(this);
   }

   function onopen(event) {
      var f = this.onopen;
      delete this.onopen;
      delete this.onabort;
      f && f(this);
   }

   function onclose(event) {
      for (var id in this.pendings) {
         try { this.pendings[id][1](); } catch (x) {/*TODO?*/}
      }
      this.pendings = {};
      this.onclose && this.onclose();
   }

   function fire(awaitens, name, data) {
      var a = awaitens[name];
      if (a)
         a.forEach(function(handler){handler(data);});
      var i = name.indexOf("/");
      if (i >= 0) {
         a = awaitens[name.substring(0,i)];
         if (a)
            a.forEach(function(handler){handler(data);});
      }
      a = awaitens["*"];
      if (a)
         a.forEach(function(handler){handler(data);});
   }

   function reply(pendings, id, ans, offset) {
      if (id in pendings) {
         var p = pendings[id];
         delete pendings[id];
         try { p[offset](ans); } catch (x) {/*TODO?*/}
      }
   }

   function onmessage(event) {
      var obj = JSON.parse(event.data);
      var code = obj[0];
      var id = obj[1];
      var ans = obj[2];
      AFB_context.token = obj[3];
      switch (code) {
      case RETOK:
         reply(this.pendings, id, ans, 0);
         break;
      case RETERR:
         reply(this.pendings, id, ans, 1);
         break;
      case EVENT:
      default:
         fire(this.awaitens, id, ans);
         break;
      }
   }

   function close() {
      this.ws.close();
      this.ws.onopen =
      this.ws.onerror =
      this.ws.onclose =
      this.ws.onmessage =
      this.onopen =
      this.onabort = function(){};
   }

   function call(method, request, callid) {
      return new Promise((function(resolve, reject){
         var id, arr;
         if (callid) {
            id = String(callid);
            if (id in this.pendings)
               throw new Error("pending callid("+id+") exists");
         } else {
            do {
               id = String(this.counter = 4095 & (this.counter + 1));
            } while (id in this.pendings);
         }
         this.pendings[id] = [ resolve, reject ];
         arr = [CALL, id, method, request ];
         if (AFB_context.token) arr.push(AFB_context.token);
         this.ws.send(JSON.stringify(arr));
      }).bind(this));
   }

   function onevent(name, handler) {
      var id = name;
      var list = this.awaitens[id] || (this.awaitens[id] = []);
      list.push(handler);
   }

   AFB_websocket.prototype = {
      close: close,
      call: call,
      onevent: onevent
   };
}
/*********************************************/
/****                                     ****/
/****                                     ****/
/****                                     ****/
/*********************************************/
return {
   context: AFB_context,
   ws: AFB_websocket
};
};
```
