#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

/* Arguments provided by the user are:
 *	0:	This program name (by the system)
 *	1:	HAProxy PID file
 *	2:	List of "VIP1:port1:tag1,VIP2:port2:tag2,...."
 *		E.g.: ./safe_reload /var/run/ha1/pid \
 *			10.47.8.252:80:FD_HOST1,10.47.8.252:443:FD_HOST2
 *			/usr/sbin/haproxy -f /etc/haproxy/hap-safe-reload.cfg
 *	3:	HAproxy executable path
 *	4-n:	haproxy arguments (no -sf or -p options, we add it ourselves)
 *
 * To reload the configuration, do the following steps:
 *	1. Make required modifications to the configuration file.
 *	2. Find the process id of safe_reload program - say 'P'
 *	3. Run "kill -USR1 $P
 *
 *	Step #2 and #3 can be merged with:
 *		pkill -USR1 safe_reload
 */

/* Constants for array sizes */
#define MAX_ARGS		32
#define MAX_VIPS		64
#define VIP_SIZE		128

/* Constants for parsing input */
#define COMMA			','
#define COLON			':'
#define NEW_LINE		'\n'

/* Logging */
#define DATE_STRING_LEN		64	/* atleast 26 bytes */
#define LOGFILE			"/var/log/safe_reload.log"

/* For signal handling */
volatile sig_atomic_t reload_signal = 1;
volatile sig_atomic_t child_signal = 0;

/*
 * This is initialized internally from socket fd's created and
 * handed over to haproxy.
 */
static int  fds[MAX_VIPS];

/* These are initialized from parameters supplied by the user */
static char vip_ips[MAX_VIPS][VIP_SIZE];
static int  vip_ports[MAX_VIPS];
static char tags[MAX_VIPS][VIP_SIZE];

/* Globals required */
static char *executable_path;
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

/* Log action */
static void log_action(char *args[])
{
	int i = 0;
	char date_string[DATE_STRING_LEN];

	get_printable_time(date_string);

	fprintf(logfp, "%s: %s is going to reload configuration.\n",
		date_string, my_name);
	fprintf(logfp, "\tArguments: ");
	while (args[i]) {
		fprintf(logfp, "%s ", args[i]);
		i++;
	}
	fprintf(logfp, "\n");
	fflush(logfp);
}

static int get_haproxy_pid()
{
	FILE *fp = fopen(pid_file, "r");
	int pid = 0;

	if (fp) {
		fscanf(fp, "%d", &pid);
		fclose(fp);
	}

	return pid;
}

/* Implement HAProxy reload by starting a new process.
 *
 * TODO: 
 *	- Send argv[5] onwards?
 *	- Integrate to haproxy directly?
 *	- Logging
 */
static void reload_signal_handler(int argc, char *argv[])
{
	char *args[MAX_ARGS];
	char pid_buffer[8];
	int pid, index;

	/* Can race with a new reload, but should not matter? */
	reload_signal = 0;

	for (index = 0; index < argc; index++)
		args[index] = argv[index];

	pid = get_haproxy_pid();
	args[index++] = "-p";
	args[index++] = pid_file;

	if (pid) {
		sprintf(pid_buffer, "%d", pid);
		args[index++] = "-sf";
		args[index++] = pid_buffer;
	}

	args[index] = NULL;

	/* Add a log entry */
	log_action(args);

	if (fork() == 0) {
		/* New process -> Child */
		execvp(args[0], args);
		perror("execvp");
		exit(1);
	}

	/* Parent returns to pause for more signals, or exit */
	signal(SIGUSR1, reload_handler);
}

static void child_signal_handler(void)
{
	int status;
	pid_t pid;

	child_signal = 0;
	while ((pid = waitpid( -1, &status, WNOHANG)) > 0);

	signal(SIGCHLD, child_handler);
}

/*
 * Parse my_arguments giving the vip:port:tag:vip:port:tag, e.g.:
 * "10.47.0.1:80:FD_HOST1,10.47.0.1:443:FD_HOST2,10.47.0.2:80:FD_HOST3"
 * Save each entry in the global arrays to be used later.
 */
int parse_arguments(char *my_arguments)
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

			strncpy(vip_ips[count], vip_start,
				vip_end - vip_start + 1);
			vip_ips[count][vip_end - vip_start + 1] = 0;;

			strncpy(port, port_start, port_end - port_start + 1);
			port[port_end - port_start + 1] = 0;;
			vip_ports[count] = atoi(port);

			strncpy(tags[count], tag_start,
				tag_end - tag_start + 1);
			tags[count][tag_end - tag_start + 1] = 0;;
		}

		++count;
		if (!*my_arguments || *my_arguments == ' ')
			break;

		if (count == MAX_VIPS) {
			fprintf(stderr, "%s: Supports atmost %d vips\n",
				my_name, MAX_VIPS);
			exit(1);
		}

		my_arguments ++;
	}

	return count;
}

void do_setup(int total)
{
	int i;
	int opt = 1;
	struct sockaddr_in server;
	char fdbuffer[8];
	char tag_buffer[128];

	signal(SIGUSR1, reload_handler);
	signal(SIGCHLD, child_handler);

	if ((logfp = fopen(LOGFILE, "a")) == NULL) {
		perror(LOGFILE);
		exit(1);
	}

	for (i = 0; i < total; i++) {
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

		/* TODO: Use inet_aton(), inet_pton(3), or getaddrinfo(3) */

		server.sin_family = AF_INET;
		server.sin_addr.s_addr = inet_addr(vip_ips[i]);
		server.sin_port = htons(vip_ports[i]);

		if (bind(fds[i], (struct sockaddr *)&server,
			 sizeof(server)) < 0) {
			perror("bind");
			exit(1);
		}

		/* Set environmental tag variable to contain the socket fd */
		sprintf(fdbuffer, "%d", fds[i]);
		if (setenv(tags[i], fdbuffer, 1)) {
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
		"%s pid-file vip-port-tag-args haproxy-path <haproxy-args>\n",
		name);
	exit(1);
}

void main(int argc, char *argv[])
{
	char *my_arguments;
	int total;

	if (argc <= 5)
		usage(argv[0]);

	my_name = argv[0];
	pid_file = argv[1];
	my_arguments = argv[2];
	executable_path = argv[3];

	total = parse_arguments(my_arguments);

	do_setup(total);

	if (daemon(1, 1)) {
		/* Failed to daemonize, do it ourselves */
		if (fork()) {
			/* Parent - exit */
			exit(0);
		}

		/* Child -> Start a new session and continue */
		setsid();
	}

	/*
	 * Wait till there is a signal from user to reload, or from a 
	 * child that it has exited.
	 */
	while (1) {

		/* Need configuration reload? */
		if (reload_signal) {
			/* Send arguments starting from haproxy executable */
			reload_signal_handler(argc - 3, &argv[3]);
		}

		/* Need to reap child? */
		if (child_signal) {
			child_signal_handler();
		}
		pause();
	}
}
