A. Introdduction:
----------------

'safe_reload' implements safe reload of haproxy, where new connections
are not dropped during a reload. safe_reload is in charge of starting
haproxy process. Invoke with the following arguments:

1:   HAProxy PID file (run time pid file, or a new file to store pid)
2:   HAproxy executable path
3:   List of vip,port,tag as arguments, E.g.:
	10.47.8.252:80:FD_HOST1,10.47.8.252:443:FD_HOST2
4-n: haproxy arguments (no -sf or -p options, safe_reload will add it
	automatically using the pid file).


B. Command line to invoke safe_reload:
---------------------------------------

	safe_reload /var/run/ha1/pid /usr/sbin/haproxy \
		10.0.0.1:80:FD_HOST1,10.0.0.2:443:FD_HOST2,20.0.0.10:80:FD_HOST3,20.0.0.11:443:FD_HOST4 \
		-f /etc/haproxy/haproxy_global.cfg \
		-f /etc/haproxy/haproxy_frontend.cfg \
		-f /etc/haproxy/haproxy_backend.cfg


C. HAProxy configuration to enable safe-reload:
-----------------------------------------------

The frontend section in the HAProxy configuration file is modified as
follows:


        frontend service-safe-reload
		bind "fd@${FD_HOST1}"
		...

	frontend safe-reload-ssl
		service-bind "fd@${FD_HOST2}" ssl crt /etc/ssl/service.pem
		...

	etc...


C. Test script to safely reload haproxy:
----------------------------------------

	#!/bin/bash

	pid=`pgrep mb_parent`
	if [ -z $pid ]
	then
		exit 1
	fi

	kill -USR1 $pid
	exit 0


D. TODO:
---------

	- Improve code to pass correct arguments to 'reload_signal_handler'.
	- Code to parse arguments can be made more robust. String parsing
	  to be made robust if wrong string is passed.
	- To be integration with systemd.
	- Improve option/arguments/command-line arguments.
	- Test multiple safe-reload invocations on same configuration files.
	- Effect of 'nbproc' to be tested.
	- Test connection drop results - before and after.
	- Other things to implement.
	- Can lua script be used to act as master for reload?
