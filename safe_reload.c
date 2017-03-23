#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

/*
 * The following arguments are provided by the user:
 *
 *	0:	This program name (by the system)
 *	1:	List of "VIP1:port1:tag1,VIP2:port2:tag2,...."
 *		E.g.: ./safe_reload \
 *			10.47.8.252:80:FD_HOST1,10.47.8.252:443:FD_HOST2 \
 *			-f /etc/haproxy/hap-safe-reload.cfg -p /var/run/ha1/pid 
 *	2-n:	haproxy arguments (no -sf option, we add it ourselves)
 *
 * All arguments from #2 onwards are passed to haproxy unmodified. We also add
 * HAProxy's '-sf' options with correct arguments, and this should not be
 * provided by the invoker.
 *
 * Execute the following steps to reload the configuration:
 *	1. Make modifications as needed to the required configuration file.
 *	2. Find the process id of the required safe_reload program - say 'P'
 *	3. Run: "kill -USR1 $P"
 *
 * For use with nbproc, the configuration file needs to be modified. f.e.,
 * with nbproc=3:
 *
 * global
 *	nbproc 3
 *
 * frontend fe-safe
 *	bind "fd@${FD_HOST1}" process 1
 *	bind "fd@${FD_HOST2}" process 2
 *	bind "fd@${FD_HOST2}" process 3
 *
 * Invoke as: safe_reload \
 *	10.1.1.2:80:FD_HOST1,10.1.1.2:80:FD_HOST2,1.1.2:80:FD_HOST3 \
 *	-f haproxy-safe-nbproc.cfg -p /var/run/ha1/pid
 */

/* Constants for array sizes */
#define MAX_VIPS		1024		/* Max vips in config file */
#define VIP_SIZE		32		/* Length of IP address */
#define TAG_SIZE		32		/* Size of the tag */
#define ERROR_SIZE		256		/* Size of error message */
#define NUM_PIDS		128		/* Maximum nbproc setting */
#define MAX_HAPROXY_ARGS	32		/* Max haproxy args */
#define MAX_ARGS		(MAX_HAPROXY_ARGS + NUM_PIDS + 2)
				/* "+ 2" for "-sf" and NULL args */
#define PID_BUFFER_SIZE		16		/* Integer size at most */

/* Constants for parsing input */
#define COMMA			','
#define COLON			':'
#define NEW_LINE		'\n'

/* Logging */
#define DATE_STRING_LEN		64	/* atleast 26 bytes */
#define LOGFILE			"/var/log/safe_reload.log"

/* For signal handling */
static volatile sig_atomic_t reload_signal = 1;
static volatile sig_atomic_t child_signal  = 0;

/*
 * This is initialized internally from socket fd's created and
 * handed over to haproxy.
 */
static int  fds[MAX_VIPS];

/* These are initialized from parameters supplied by the user */
static struct {
	int  vip_port;
	char vip_ip[VIP_SIZE];
	char vip_tag[TAG_SIZE];
} vip_details[MAX_VIPS];

/* Globals required */
static char *my_name;
static char *pid_file;
static FILE *logfp;

/* Inform main() that a configuration reload is required */
static void reload_handler(int arg)
{
	reload_signal = 1;
}

/* Inform main() that a child has exited to reap it to prevent zombies */
static void child_handler(int arg)
{
	child_signal = 1;
}

/* Return a string containing the current date and time */
static void get_printable_time(char *date_string)
{
	struct timeval date;
	struct tm tm;

	gettimeofday(&date, NULL);
	localtime_r(&date.tv_sec, &tm);

	if (asctime_r(&tm, date_string) == NULL)
		bzero(date_string, sizeof(date_string));
	else if (date_string[strlen(date_string) - 1] == NEW_LINE)
		date_string[strlen(date_string) - 1] = 0;
}

/* Log information or errors */
static void log_info(char *msg)
{
	char date_string[DATE_STRING_LEN];

	get_printable_time(date_string);

	fprintf(logfp, "%s: %s (%d): %s\n", date_string, my_name, getpid(),
		msg);
	fprintf(logfp, "--------------------------------------------------\n");
	fflush(logfp);
}

/* Log the reconfiguration action with it's arguments */
static void log_action_arguments(int argc, char *args[])
{
	int index = 0;
	char date_string[DATE_STRING_LEN];

	get_printable_time(date_string);

	fprintf(logfp, "%s: %s (%d) is going to reload configuration.\n",
		date_string, my_name, getpid());
	fprintf(logfp, "Executing command (#args: %d): ", argc);
	while (args[index]) {
		fprintf(logfp, "%s ", args[index]);
		index++;
	}
	fprintf(logfp, "\n");
	fprintf(logfp, "--------------------------------------------------\n");
	fflush(logfp);
}

/*
 * Copy the list of PIDs of current haproxy process's into pids, and return
 * the count of running processes.
 */
static int get_haproxy_pids(char pids[][PID_BUFFER_SIZE])
{
	FILE *fp = fopen(pid_file, "r");
	char tmp[PID_BUFFER_SIZE];
	int  npids = 0;

	if (fp) {
		while (fscanf(fp, "%s", tmp) == 1) {
			if (npids == NUM_PIDS) {
				log_info("Too many pids, not sending more");
				break;
			}

			strcpy(pids[npids], tmp);
			npids++;
		}

		fclose(fp);
	}

	return npids;
}

void print_args(char *args[])
{
	int index = 0;

	while (args[index]) {
		printf("%s ", args[index]);
		index++;
	}
	printf("\n");
}

static int add_child_args(int argc, char *argv[], char *child_args[],
			  char pid_buffer[NUM_PIDS][PID_BUFFER_SIZE])
{
	int  pid, npids, index;

	/* First copy haproxy command name */
	child_args[0] = "haproxy";

	/* Next copy haproxy path and all it's arguments */
	for (index = 0; index < argc; index++)
		child_args[index + 1] = argv[index];

	/* Increment index by 1 for "haproxy" that was added */
	index++;

	/* Next find list of existing pids to be killed, and pass to haproxy */
	npids = get_haproxy_pids(pid_buffer);

	/* Reload option with -sf and list of pids */
	if (npids) {
		/* NOTE: child_args should not overflow */
		child_args[index++] = "-sf";
		for (pid = 0; pid < npids; pid++)
			child_args[index++] = pid_buffer[pid];
	}

	/* Terminate arguments */
	child_args[index] = NULL;

	return index;
}

/* Delayed handler to implement safe HAProxy reload. */
static void reload_signal_handler(int argc, char *argv[])
{
	char pid_buffer[NUM_PIDS][PID_BUFFER_SIZE];
	char *args[MAX_ARGS];
	int total_args, ret;

	reload_signal = 0;

#ifdef SIGNAL_RACE
	/*
	 * This function could have a small race with a new reload, but this
	 * should not matter. We will atmost do an unnecessary reload as an
	 * effect of this race. Hence this code is commented out for now.
	 */

	/* First mask signals */
	sigfillset(&mask_set);
	sigprocmask(SIG_SETMASK, &mask_set, &old_set);
	/* Then execute all the steps */
	/* ... */
	/* Then unmask signals */
	sigprocmask(SIG_SETMASK, &old_set, NULL);
#endif

	/* Create arguments to pass to child */
	total_args = add_child_args(argc, argv, args, pid_buffer);

	/* Add a log entry for action and arguments */
	log_action_arguments(total_args, args);

	/* And invoke haproxy */
	if ((ret = fork()) == 0) {
		char error_string[ERROR_SIZE];

		/* New process -> Child */
		execvp(args[0], args);

		/* Should never reach here */
		strcpy(error_string, argv[0]);
		strcat(error_string, ": ");
		strcat(error_string, strerror(errno));
		log_info(error_string);
		exit(1);
	} else if (ret < 0) {
		log_info("Unable to reconfigure due to fork failure");
	}

	/* Parent returns to pause for more signals, or exit */
	signal(SIGUSR1, reload_handler);
}

/* Delayed handler when a child exits */
static void child_signal_handler(void)
{
	int status;

	child_signal = 0;
	while (waitpid(-1, &status, WNOHANG) > 0);
		/* One child exited, try for more */

	signal(SIGCHLD, child_handler);
}

/*
 * Parse my_arguments of the form "vip:port:tag,vip:port:tag". E.g.:
 * "10.47.0.1:80:FD_HOST1,10.47.0.1:443:FD_HOST2,10.47.0.2:80:FD_HOST3".
 * Save each entry in the global arrays to be used later.
 */
static int parse_arguments(char *my_arguments)
{
	int count = 0;
	char *vip_start, *vip_end;
	char *port_start, *port_end;
	char *tag_start, *tag_end;
	char port[128];

	while (*my_arguments) {
		while (*my_arguments && *my_arguments != COMMA) {
			vip_start = my_arguments;
			while (*my_arguments && *my_arguments != COLON )
				my_arguments ++;
			if (*my_arguments != COLON) {
				fprintf(stderr, "Bad input at VIP\n");
				exit(1);
			}
			vip_end = my_arguments - 1;

			port_start = ++my_arguments;
			while (*my_arguments && *my_arguments != COLON )
				my_arguments ++;
			if (*my_arguments != COLON) {
				fprintf(stderr, "Bad input at PORT\n");
				exit(1);
			}
			port_end = my_arguments - 1;

			tag_start = ++my_arguments;
			while (*my_arguments && *my_arguments != COMMA )
				my_arguments ++;
			if (*my_arguments && *my_arguments != COMMA) {
				fprintf(stderr, "Bad input at TAG\n");
				exit(1);
			}
			tag_end = my_arguments - 1;

			strncpy(vip_details[count].vip_ip, vip_start,
				vip_end - vip_start + 1);
			vip_details[count].vip_ip[vip_end - vip_start + 1] = 0;

			strncpy(port, port_start, port_end - port_start + 1);
			port[port_end - port_start + 1] = 0;;

			strncpy(vip_details[count].vip_tag, tag_start,
				tag_end - tag_start + 1);
			vip_details[count].vip_tag[tag_end-tag_start+1] = 0;;

			vip_details[count].vip_port = atoi(port);

			++count;
			if (!*my_arguments)
				break;
		}

		if (!*my_arguments)
			break;

		if (count == MAX_VIPS) {
			fprintf(stderr, "%s: Supports atmost %d vips\n",
				my_name, MAX_VIPS);
			exit(1);
		}

		my_arguments ++;
	}

out:
	return count;
}

/*
 * Perform various actions:
 *	1. Setup signal handlers.
 *	2. Open sockets for each VIP.
 *	3. Set socket options for REUSEADDR/REUSEPORT
 *	4. Bind each socket to the VIP:port, but do not LISTEN
 *	5. Export the tag environment variable with the fd of this socket.
 */
static void do_setup(int total)
{
	int i, ret;
	int opt = 1;
	char fdbuffer[8];

	signal(SIGUSR1, reload_handler);
	signal(SIGCHLD, child_handler);

	for (i = 0; i < total; i++) {
		struct sockaddr_in server;

		if ((fds[i] = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket");
			exit(1);
		}

		if (setsockopt(fds[i], SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
			       sizeof(opt)) < 0) {
			perror("setsockopt reuseaddr");
			exit(1);
		}

		if (setsockopt(fds[i], SOL_SOCKET, SO_REUSEPORT, (char *)&opt,
			       sizeof(opt)) < 0) {
			perror("setsockopt reuseport");
			exit(1);
		}

		server.sin_family = AF_INET;
		server.sin_port = htons(vip_details[i].vip_port);
		ret = inet_pton(AF_INET, vip_details[i].vip_ip,
				&server.sin_addr);
		if (ret != 1) {
			fprintf(stderr, "inet_pton for VIP: %s, ret: %d\n",
				vip_details[i].vip_ip, ret);
			exit(1);
		}

		if (bind(fds[i], (struct sockaddr *)&server,
			 sizeof(server)) < 0) {
			perror("bind");
			exit(1);
		}

		/* Set environmental tag variable to contain the socket fd */
		sprintf(fdbuffer, "%d", fds[i]);
		if (setenv(vip_details[i].vip_tag, fdbuffer, 1)) {
			perror("setenv");
			exit(1);
		}
	}
}

/*
 * Print the command line usage and exit.
 */
static void usage(char *name)
{
	fprintf(stderr,
		"%s vip:port:tag,... haproxy-path <haproxy-args>\n",
		name);
	exit(1);
}

/* Open the log file for appending messages. */
static void enable_logging(void)
{
	if ((logfp = fopen(LOGFILE, "a")) == NULL) {
		perror(LOGFILE);
		exit(1);
	}
}

/* Note: argv[] is always NULL terminated */
static char *find_pid_file(char *argv[])
{
	int index = 0;

	while (argv[index]) {
		if (!strcmp(argv[index], "-p"))
			return argv[index + 1];	/* can be NULL */
		index++;
	}

	return NULL;
}

void main(int argc, char *argv[])
{
	char *my_arguments;
	int num_haproxy_args;
	char **haproxy_args;
	int total;

	if (argc < 6) {
		usage(argv[0]);
	} else if (argc - 1 > MAX_HAPROXY_ARGS) {
		fprintf(stderr, "%s: Maximum of %d arguments for haproxy\n",
			argv[0], MAX_HAPROXY_ARGS);
		exit(1);
	}

	my_name = argv[0];
	my_arguments = argv[1];


	pid_file = find_pid_file(&argv[2]);
	if (!pid_file) {
		fprintf(stderr, "%s: -p <pid-file> is mandatory\n", argv[0]);
		exit(1);
	}

	enable_logging();

	total = parse_arguments(my_arguments);
	if (!total) {
		log_info("No VIPs found in arguments");
		fprintf(stderr, "No VIPs found in arguments\n");
		exit(1);
	}

	do_setup(total);

	if (daemon(1, 1)) {
		int ret;

		/* Failed to daemonize, do it ourselves */
		if ((ret = fork()) > 0) {
			/* Parent - exit */
			exit(0);
		} else if (ret < 0) {
			log_info("Unable to daemonize due to fork failure");
		}

		/* Child -> Start a new session and continue */
		setsid();
	}

	log_info("Starting up");

	/*
	 * We were invoked as follows:
	 *	./safe_reload tags -f safe-hap.cfg -p pid-file ...
	 */
	num_haproxy_args = argc - 2;
	haproxy_args = &argv[2];

	/*
	 * Wait till there is a signal from user to reload, or from a
	 * child that it has exited.
	 */
	while (1) {
		/* Check if we need configuration reload */
		if (reload_signal) {
			/* Ask HAProxy to reload */
			reload_signal_handler(num_haproxy_args, haproxy_args);
		}

		/* Check if we need to reap child */
		if (child_signal) {
			child_signal_handler();
		}

		/* Do nothing till another signal arrives */
		pause();
	}
}
