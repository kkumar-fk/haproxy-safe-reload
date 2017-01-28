		Safe HAProxy reload without dropping connections
		--------------------------------------------------

A. Command line argument to invoke safe_reload:
------------------------------------------------
	safe_reload /var/run/ha1/pid /usr/sbin/haproxy 10.0.0.1:80:FD_HOST1,10.0.0.2:443:FD_HOST2,20.0.0.10:80:FD_HOST3,20.0.0.11:443:FD_HOST4 -f /etc/haproxy/haproxy_global.cfg -f /etc/haproxy/haproxy_frontend.cfg -f /etc/haproxy/haproxy_backend.cfg


B. Test script to safely reload haproxy:
----------------------------------------
	#!/bin/bash

	pid=`pgrep mb_parent`
	if [ -z $pid ]
	then
		exit 1
	fi

	kill -USR1 $pid
	exit 0

C. TODO:
---------
	- Test multiple safe-reload invocations on same configuration files.
	- Effect of 'nbproc' to be tested.
	- Integration with systemd
	- Improve arguments/command-line arguments.

