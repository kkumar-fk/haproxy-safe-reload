A. Introduction:
----------------

'safe_reload' implements safe reload of haproxy, where new connections
are not dropped during a reload. safe_reload is in charge of starting
haproxy process. Invoke with the following arguments:

1)   HAProxy PID file (run time pid file, or a new file to store pid)
2)   List of vip,port,tag as arguments, E.g.:
	10.47.8.252:80:FD_HOST1,10.47.8.252:443:FD_HOST2
3)   HAproxy executable path
4-n) haproxy arguments (no -sf or -p options, safe_reload will add it
	automatically using the pid file).


B. Command line to invoke safe_reload:
---------------------------------------

	safe_reload /var/run/ha1/pid \
		10.0.0.1:80:FD_HOST1,10.0.0.2:443:FD_HOST2 \
		/usr/sbin/haproxy -f /etc/haproxy/haproxy_global.cfg \
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
		bind "fd@${FD_HOST2}" ssl crt /etc/ssl/service.pem
		...
	etc...


C. Test script to safely reload haproxy:
----------------------------------------

Send SIGUSR1 to the correct safe_reload daemon to ask it to reload the
configuration. The following script can be used, but requires to be
modified when there are multiple safe_reload's running for multiple
haproxy configuration files:

	#!/bin/bash

	# Assumes only one safe_reload is running, else find the PID of the
	# required safe_reload program.
	pid=`pgrep safe_reload`
	if [ -z $pid ]
	then
		exit 1
	fi

	kill -USR1 $pid
	exit 0


D. 'nbproc' support:
---------------------

For use with nbproc, the configuration file has these contents, for e.g.
with nbproc=3:
 
	global
		nbproc 3

	frontend fe-safe
		bind "fd@${FD_HOST1}" process 1
		bind "fd@${FD_HOST2}" process 2
		bind "fd@${FD_HOST3}" process 3

Invoke safe_reload as follows:
	safe_reload /var/run/ha1/pid \
	10.47.8.25:80:FD_HOST1,10.47.8.25:80:FD_HOST2,10.47.8.25:80:FD_HOST3 \
	/usr/sbin/haproxy -f haproxy-safe-nbproc.cfg


E. Configuration supported:
----------------------------

1. Multiple safe-reload invocations on same configuration files - works.
2. Sending SIGUSR1 to any safe-reload processes - works.
3. 'nbproc' - tested and works fine.


F. Testing done:
-----------------

1. Test on multiple safe-reload.
2. Signals to multiple safe-reload processes.
3. Performance testing.
4. Logging of multiple safe-reload done.
5. Test results:
	Note: Pause between reloads need to be very small to catch errors
	during an actual reload, and not show success during the non-reload
	times. Otherwise we measure connections drop during non-reload times
	which is almost always 0, and is useless. Increase frequency of
	reload even more to find actual failure rate during a reload. The
	test script does:

	1. Reload haproxy every 300 ms (haproxy-1.6.3 used for both tests)
	2. Run ab from 2 different baremetals using this script:
		while :
		do
			ab -c 10000 -n 100000 http://10.47.8.252/128
		done > /tmp/out 2>&1 &
		sleep 600
		kill %%
	3. Calculate percentage failure:


G. Performance Results on 16.04 box:
------------------------------------

			Original HAProxy reload:
	Number of 100% success runs:	0/3765 iterations
	Total requests:			279104 + 1844826 = 2123930
	Total failures:			3765
	Failure rate:			3765/2123930*100 = 0.18%

			Safe HAProxy reload:
	Number of 100% success runs:	158/158 iterations
	Total requests:			7800000 + 7800000 = 15600000
						(634% increase)
	Total failures:			0
	Failure rate:			0%

Testing with nbproc not yet done for both original vs new.


H. Configd/other utility changes:
----------------------------------

<TBD> Essentially, for a reload, configd needs to find the correct safe_reload
process and send a SIGUSR1 signal to it. Configuration generation has minor
changes too <TBD>


I. TODO:
---------

	- Improve option/arguments/command-line arguments.
	- Code to parse arguments can be made more robust. String parsing
	  to be made robust if wrong string is passed.
	- To be integration with systemd.
