#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

/* Arguments provided by the user are:
 *	0:	This program name (by the system)
 *	1:	HAProxy PID file
 *	2:	HAproxy executable path
 *	3:	List of "VIP1:port1:tag1,VIP2:port2:tag2,...."
 *		E.g.: ./safe_reload /var/run/ha1/pid /usr/sbin/haproxy \
 *			10.47.8.252:80:FD_HOST1,10.47.8.252:443:FD_HOST2
 *			-f /etc/haproxy/haproxy-safe-reload.cfg
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
#define COMMA	','
#define COLON	':'

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

#if DEBUG
/* Print arguments being passed while invoking haproxy */
static void print_args(char *args[])
{
	int i = 0;

	printf("%s is going to invoke: ", my_name);
	while (args[i]) {
		printf("%s ", args[i]);
		i++;
	}
	printf("\n");
}
#endif

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
 */
static void reload_signal_handler(int argc, char *argv[])
{
	char *args[MAX_ARGS];
	char pid_buffer[8];
	int i, pid, index;

	/* Can race with a new reload, but should not matter? */
	reload_signal = 0;

	args[0] = executable_path;

	for (i = 4; i < argc; i++)
		args[i - 3] = argv[i];
	index = i - 3;

	pid = get_haproxy_pid();
	args[index++] = "-p";
	args[index++] = pid_file;

	if (pid) {
		sprintf(pid_buffer, "%d", pid);
		args[index++] = "-sf";
		args[index++] = pid_buffer;
	}

	args[index++] = NULL;

#if DEBUG
	print_args(args);
#endif

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
 * Parse arguments giving the vip:port:tag:vip:port:tag, e.g.:
 * "10.47.0.1:80:FD_HOST1,10.47.0.1:443:FD_HOST2,10.47.0.2:80:FD_HOST3"
 * Save each entry in the global arrays to be used later.
 */
int parse_arguments(char *arguments)
{
	int count = 0;
	char *vip_start, *vip_end;
	char *port_start, *port_end;
	char *tag_start, *tag_end;
	char port[128];

	while (*arguments) {
		while (*arguments && *arguments != COMMA) {
			vip_start = arguments;
			while (*arguments && *arguments != COLON )
				arguments ++;
			if (*arguments != COLON) {
				fprintf(stderr, "Bad input at VIP\n");
				exit(1);
			}
			vip_end = arguments - 1;

			port_start = ++arguments;
			while (*arguments && *arguments != COLON )
				arguments ++;
			if (*arguments != COLON) {
				fprintf(stderr, "Bad input at PORT\n");
				exit(1);
			}
			port_end = arguments - 1;

			tag_start = ++arguments;
			while (*arguments && *arguments != COMMA )
				arguments ++;
			if (*arguments && *arguments != COMMA) {
				fprintf(stderr, "Bad input at TAG\n");
				exit(1);
			}
			tag_end = arguments - 1;

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
		if (!*arguments || *arguments == ' ')
			break;

		if (count == MAX_VIPS) {
			fprintf(stderr, "%s: Supports atmost %d vips\n",
				my_name, MAX_VIPS);
			exit(1);
		}

		arguments ++;
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
		"%s pid-file haproxy-path vip-port-tag-args <haproxy-args>\n",
		name);
	exit(1);
}

void main(int argc, char *argv[])
{
	char *arguments;
	int total;

	if (argc <= 5)
		usage(argv[0]);

	my_name = argv[0];
	pid_file = argv[1];
	executable_path = argv[2];
	arguments = argv[3];

	total = parse_arguments(arguments);

	do_setup(total);

	/*
	 * Wait till there is a signal from user to reload, or from a 
	 * child that it has exited.
	 */
	while (1) {
		if (reload_signal)
			reload_signal_handler(argc, argv);
		if (child_signal)
			child_signal_handler();
		pause();
	}
}
