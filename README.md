		Safe HAProxy reload without dropping connections
		______________________________________________________
		
		


'safe_reload' implements safe reload of haproxy. Invoke with the following
arguments:

1:   HAProxy PID file (run time pid file, or a new file to store pid)
2:   HAproxy executable path
3:   List of vip,port,tag as arguments, E.g.:
	10.47.8.252:80:FD_HOST1,10.47.8.252:443:FD_HOST2
4-n: haproxy arguments (no -sf or -p options, safe_reload will add it
	automatically using the pid file).



A. Command line to invoke safe_reload:
---------------------------------------

	safe_reload /var/run/ha1/pid /usr/sbin/haproxy \
		10.0.0.1:80:FD_HOST1,10.0.0.2:443:FD_HOST2,20.0.0.10:80:FD_HOST3,20.0.0.11:443:FD_HOST4 \
		-f /etc/haproxy/haproxy_global.cfg \
		-f /etc/haproxy/haproxy_frontend.cfg \
		-f /etc/haproxy/haproxy_backend.cfg



B. HAProxy configuration to enable safe-reload:
-----------------------------------------------

The frontend section in the HAProxy configuration file is modified as
follows:

        frontend fk-safe-reload
		bind "fd@${FD_HOST1}"
		...

	frontend fk-safe-reload-ssl
		bind "fd@${FD_HOST2}" ssl crt /etc/ssl/haproxy/ssl-file
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
	- Test multiple safe-reload invocations on same configuration files.
	- Effect of 'nbproc' to be tested.
	- Integration with systemd
	- Improve option/arguments/command-line arguments.
	- Test results (before and after).
	- Other things to implement.
