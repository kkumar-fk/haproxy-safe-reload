#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>

#include <unistd.h>
#include <sys/syscall.h>

int gettid(void)
{
#ifdef SYS_gettid
pid_t tid = syscall(SYS_gettid);
#else
#error "SYS_gettid is not available on this system"
#endif

return tid;
}

/*
 * Arguments: Either the user can provide a single argument which is a
 * file containing all arguments, else the user provides all arguments
 * on the command line. If the user specifies a single argument, it is
 * assumed to be a file containing the following lines:
 *	ARGUMENTS <all-haproxy-arguments>
 *	VIP <vip>
 *	PORT <port#>
 *	TAG <tag>
 * VIP, PORT and TAG can repeat as many times as required. Each TAG MUST
 * be unique.
 *
 * However, if the user provides command line arguments, it is in the
 * following order:
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

#define HAPROXY_EXECUTABLE	"haproxy"

/* Get status of the last reload by connecting to this localhost socket */
#define RELOAD_PORT		25111

/* Logging */
#define DATE_STRING_LEN		64	/* atleast 26 bytes */
#define LOGFILE			"/var/log/safe_reload.log"

/* Fork result */
#define CHILD			0
#define PARENT			1

/* For signal handling */
volatile sig_atomic_t reload_signal = 1;
volatile sig_atomic_t child_signal  = 0;

/* These are initialized from parameters supplied by the user */
int num_haproxy_args;
int total_vips = 0;
struct vd {
	int  vip_fd;
	int  vip_port;
	char vip_ip[VIP_SIZE];
	char vip_tag[TAG_SIZE];
};

struct vd vip_details[MAX_VIPS];

/*
 * Backup of earlier vip configurations. This is required when doing a
 * reload via a file.
 */
struct vd vip_details_old[MAX_VIPS];
int total_vips_old = 0;

/* Globals required */
char *my_name;
char *pid_file;
FILE *logfp;

/* Upon startup or reload, read arguments from file if this is !NULL */
char *my_filename = NULL;

/* All arguments to be passed to haproxy - un-optimized, recreate each time */
char *haproxy_args[MAX_ARGS];

/* Debug string for logging */
char debug_str[512];

/* Whether any action was taken during re-configuration */
int action_taken = 0;

/* Number of count load/reload happened */
int reload_count = 0;

/* Reload status */
int reload_status = 0;

/* Inform main() that a configuration reload is required */
void reload_handler(int arg)
{
	reload_signal = 1;
}

/* Inform main() that a child has exited to reap it to prevent zombies */
void child_handler(int arg)
{
	child_signal = 1;
}

/* Return a string containing the current date and time */
void get_printable_time(char *date_string)
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

void log_end_of_block(void)
{
	fprintf(logfp,
		"----------------------------------------------------------\n");
	fflush(logfp);
}

/* Log information or errors */
void log_info(char *msg)
{
	char date_string[DATE_STRING_LEN];

	get_printable_time(date_string);

	fprintf(logfp, "%s: PID: %d, %s\n", date_string, getpid(), msg);
	fflush(logfp);
}

/* Log the reconfiguration action with it's arguments */
void log_action_arguments(int argc, char *args[])
{
	int index = 0;
	char date_string[DATE_STRING_LEN];
	char *str;

	get_printable_time(date_string);

	if (!reload_count)
		str = "Loading HAProxy";
	else
		str = "Re-loading HAProxy";

	fprintf(logfp, "%s (%d): %s configuration (%d).\n",
		date_string, getpid(), str, reload_count);
	fprintf(logfp, "Executing command (#args: %d): ", argc);

	while (args[index]) {
		fprintf(logfp, "%s ", args[index]);
		index++;
	}
	fprintf(logfp, "\n");
}

/*
 * Copy the list of PIDs of current haproxy process's into pids, and return
 * the count of running processes.
 */
int get_haproxy_pids(char pids[][PID_BUFFER_SIZE])
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

/*
 * This function creates HAProxy argument list from haproxy_args[], and
 * adds "-sf <pid1 pid2 ...>" to create the full HAProxy arguments.
 */
int add_haproxy_args(char *child_args[],
		     char pid_buffer[NUM_PIDS][PID_BUFFER_SIZE])
{
	int  pid, npids, index;

	/* First copy haproxy cmd name, and all static arguments */
	for (index = 0; index <= num_haproxy_args; index++)
		child_args[index] = haproxy_args[index];

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

	/* Return number of arguments */
	return index;
}

int get_haproxy_socket(int i)
{
	struct sockaddr_in server;
	int ret, opt = 1;
	char fdbuffer[8];

	errno = 0;
	if ((vip_details[i].vip_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return errno;
	}

	if (setsockopt(vip_details[i].vip_fd, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&opt, sizeof(opt)) < 0) {
		perror("REUSEADDR");
		return errno;
	}

	if (setsockopt(vip_details[i].vip_fd, SOL_SOCKET, SO_REUSEPORT,
		       (char *)&opt, sizeof(opt)) < 0) {
		perror("REUSEPORT");
		return errno;
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(vip_details[i].vip_port);

	ret = inet_pton(AF_INET, vip_details[i].vip_ip, &server.sin_addr);
	if (ret != 1) {
		fprintf(stderr, "inet_pton for VIP: %s, ret: %d\n",
			vip_details[i].vip_ip, ret);
		return errno;
	}

	if (bind(vip_details[i].vip_fd, (struct sockaddr *)&server,
		 sizeof(server)) < 0) {
		perror("bind");
		return errno;
	}

	/* Set environmental tag variable to contain the socket fd */
	sprintf(fdbuffer, "%d", vip_details[i].vip_fd);
	if (setenv(vip_details[i].vip_tag, fdbuffer, 1)) {
		perror("setenv");
		return errno;
	}

	sprintf(debug_str, "Opened socket, tag: %s fd: %d\n",
		vip_details[i].vip_tag, vip_details[i].vip_fd);
	log_info(debug_str);

	return 0;
}

/* Search for 'tag' in old vip_details v, and return slot if found */
int get_tag_index(char *tag, struct vd *v, int max_slots)
{
	int i;

	for (i = 0; i < max_slots; i++) {
		if (!strcmp(v[i].vip_tag, tag))
			return i;
	}

	return -1;
}

/*
 * Following conditions should be met:
 * A. If same tag is present in earlier configuration too:
 *	- It must have same vip/port
 *	- Copy fd from previous config to new config.
 *    Else:
 *	- Close old socket
 *	- Open new socket and save it.
 * B. If old configuration had a tag that is not present in new
 *    configuration:
 *	- close old socket
 */
int validate_old_new_configs(void)
{
	int i, old_index;

	if (!total_vips_old)
		return 1;

	for (i = 0; i < total_vips; i++) {
		old_index = get_tag_index(vip_details[i].vip_tag,
					  vip_details_old, total_vips_old);
		if (old_index >= 0) {
			if ((vip_details[i].vip_port !=
			     vip_details_old[old_index].vip_port) ||
			     strcmp(vip_details[i].vip_ip,
				    vip_details_old[old_index].vip_ip)) {
				sprintf(debug_str, "Tag: %s -> %s:%d to %s:%d",
					vip_details[i].vip_tag,
					vip_details_old[old_index].vip_ip,
					vip_details_old[old_index].vip_port,
					vip_details[i].vip_ip,
					vip_details[i].vip_port);
				log_info(debug_str);
				return 0;
			}

			vip_details[i].vip_fd =
				vip_details_old[old_index].vip_fd;
			continue;
		}

		/* Did not match any earlier socket, open new socket */
		if (get_haproxy_socket(i)) {
			log_info(strerror(errno));
			/* Any error handling more? Reload may fail. */
		} else
			action_taken = 1;

	}

	return 1;
}

void close_unused_sockets(int type)
{
	int i;
	int new_index;

	/* If any old tags are not there in the new, close the old one */
	for (i = 0; i < total_vips_old; i++) {
		new_index = get_tag_index(vip_details_old[i].vip_tag,
					  vip_details, total_vips);

		if (new_index == -1) {
			close(vip_details_old[i].vip_fd);
			if (type == PARENT) {
				sprintf(debug_str,
					"Closed socket, tag: %s fd: %d\n",
					vip_details_old[i].vip_tag,
					vip_details_old[i].vip_fd);
				log_info(debug_str);
			} else	
				unsetenv(vip_details_old[i].vip_tag);

			action_taken = 1;
		}
	}
}

int find_index_of(char *keys[], char *key)
{
	int index = 0;

	while (keys[index]) {
		if (!strcmp(keys[index], key))
			return index;
		index++;
	}

	fprintf(stderr, "BUG: Key %s was not found\n", key);
	exit(1);
}

/*
 * Contents of the file are strictly in the following order:
 *	ARGUMENTS <all-haproxy-arguments-on-same-line>
 *	VIP <vip>
 *	PORT <port#>
 *	TAG <tag>
 */
int parse_file(char *filename, int *num_args)
{
	char *keys[] = {"ARGUMENTS", "VIP", "PORT", "TAG", NULL};
	int key_index = 0, nvips = 0;
	int index_of_vip;
	char line[1024];
	FILE *fp;
	int i;

	*num_args = 0;
	if ((fp = fopen(filename, "r")) == NULL) {
		perror(filename);
		exit(1);
	}

	index_of_vip = find_index_of(keys, "VIP");

	for (i = 0; i < MAX_HAPROXY_ARGS; i++) {
		free(haproxy_args[i]);
		haproxy_args[i] = NULL;
	}

	haproxy_args[0] = strdup(HAPROXY_EXECUTABLE);

	while (fgets(line, sizeof(line) -1, fp)) {
		char *arguments;
		char key[128], value[512];
		int offset;

		sscanf(line, "%s %n%s", key, &offset, value);

		if (strcmp(key, keys[key_index])) {
			fprintf(stderr, "Unexpected key: %s, expected: %s\n",
				key, keys[key_index]);
			exit(1);
		}

		if (!strcmp(key, "ARGUMENTS")) {
			char *ptr = line + offset;
			int get_pid_file = 0;
			char *token;

			if (strlen(ptr) > 0 && ptr[strlen(ptr) - 1] == NEW_LINE)
				ptr[strlen(ptr) - 1] = 0;

			i = 1;
			while ((token = strsep(&ptr, " "))) {
				if (get_pid_file) {
					pid_file = strdup(token);
					get_pid_file = 0;
				}

				haproxy_args[i] = strdup(token);
				if (!strcmp(token, "-p"))
					get_pid_file = 1;

				++(*num_args);
				i++;
			}
		} else if (!strcmp(key, "VIP")) {
			strcpy(vip_details[nvips].vip_ip, value);
		} else if (!strcmp(key, "PORT")) {
			vip_details[nvips].vip_port = atoi(value);
		} else if (!strcmp(key, "TAG")) {
			strcpy(vip_details[nvips].vip_tag, value);
		} else {
			fprintf(stderr, "Unknown key: %s\n", key);
			exit(1);
		}

		key_index++;
		if (keys[key_index] == NULL) {
			nvips++;
			key_index = index_of_vip;
		}
	}

	fclose(fp);
	return nvips;
}

/* Ensure all tags are unique - simple brute force is ok for a 1 time task */
int validate_user_data(void)
{
	int i, j;

	for (i = 0; i < total_vips - 1; i++) {
		for (j = i + 1; j < total_vips; j++) {
			if (!strcmp(vip_details[i].vip_tag,
				    vip_details[j].vip_tag)) {
				return 0;
			}
		}
	}

	return 1;
}

/*
 * Delayed handler to implement safe HAProxy reload. This function
 * sends the specified arguments to the correct haproxy process and
 * relies on haproxy to do the reload. Since the socket fd's are kept
 * open by us, haproxy will not close the socket, which otherwise
 * would have resulted in dropped connections during the reload.
 *
 * TODO:
 *	- In all cases, args must be done out of this function, static
 *	  for command line and dynamic for file based.
 *	- API to find last reload status
 *	- Change from new thread to a poll based.
 */
void reload_signal_handler(void)
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

	/* Create arguments to pass to HAProxy */
	total_args = add_haproxy_args(args, pid_buffer);

	/* Add a log entry for action and arguments */
	log_action_arguments(total_args, args);

	/* And invoke haproxy */
	if ((ret = fork()) == 0) {
		if (my_filename) {
			/* Child needs to close unused fd's. */
			close_unused_sockets(CHILD);
		}

		/* New process -> Child */
		execvp(args[0], args);

		/* Should never reach here */
		sprintf(debug_str, "%s:%s", haproxy_args[0], strerror(errno));
		log_info(debug_str);
		exit(1);
	} else if (ret < 0) {
		reload_status = errno;
		log_info("Unable to reconfigure due to fork failure");
	} else {
		/*
		 * Parent also needs to close unused fd's, but this is done
		 * after old haproxy dies in the child exit handler.
		 */
		;
	}

	/* Parent returns to pause for more signals, or exit */
	signal(SIGUSR1, reload_handler);
}

/* Delayed handler when a child exits */
void child_signal_handler(void)
{
	int status;
	char *str;

	child_signal = 0;
	while (waitpid(-1, &status, WNOHANG) > 0);
		/* One child exited, try for more */

	/* Now that old haproxy is dead, close all unused sockets */
	if (my_filename)
		close_unused_sockets(PARENT);

	if (!reload_count)
		str = "Loading";
	else
		str = "Re-loading";

	if (action_taken)
		sprintf(debug_str, "Action taken during %s", str);
	else
		sprintf(debug_str, "No action required during %s", str);
	log_info(debug_str);

	log_end_of_block();

	action_taken = 0;
	signal(SIGCHLD, child_handler);
}

/*
 * Perform various actions on start up:
 *	1. Setup signal handlers.
 *	2. Open sockets for each VIP.
 *	3. Set socket options for REUSEADDR/REUSEPORT
 *	4. Bind each socket to the VIP:port, but do not LISTEN
 *	5. Export the tag environment variable with the fd of this socket.
 */
/*
 * Print the command line usage and exit.
 */
void usage(char *name)
{
	fprintf(stderr,
		"%s <file> or \"vip:port:tag,... <haproxy-args>\"\n",
		name);
	exit(1);
}

/* Open the log file for appending messages. */
void enable_logging(void)
{
	if ((logfp = fopen(LOGFILE, "a")) == NULL) {
		perror(LOGFILE);
		exit(1);
	}
}

/* Note: argv[] is always NULL terminated */
char *find_pid_file(char *argv[])
{
	int index = 0;

	while (argv[index]) {
		if (!strcmp(argv[index], "-p"))
			return argv[index + 1];	/* can be NULL */
		index++;
	}

	return NULL;
}

int create_haproxy_args(int total_args, char *args[])
{
	int i;

	bzero(haproxy_args, sizeof(haproxy_args));

	haproxy_args[0] = strdup(HAPROXY_EXECUTABLE);
	for (i = 0; i < total_args; i++)
		haproxy_args[i + 1] = args[i];
	/* This is NULL terminated anyway */

	return total_args;
}

/*
 * Parse command line arguments of the form "vip:port:tag,vip:port:tag". E.g.:
 * "10.47.0.1:80:FD_HOST1,10.47.0.1:443:FD_HOST2,10.47.0.2:80:FD_HOST3".
 * Save each entry in the global arrays to be used later.
 */
int parse_cmdline_arguments(int total_args, char *tag_arguments,
			    char *remaining_args[], int *num_args)
{
	int count = 0;
	char *vip_start, *vip_end;
	char *port_start, *port_end;
	char *tag_start, *tag_end;
	char port[128];

	while (*tag_arguments) {
		while (*tag_arguments && *tag_arguments != COMMA) {
			vip_start = tag_arguments;
			while (*tag_arguments && *tag_arguments != COLON )
				tag_arguments ++;
			if (*tag_arguments != COLON) {
				fprintf(stderr, "Bad input at VIP\n");
				exit(1);
			}
			vip_end = tag_arguments - 1;

			port_start = ++tag_arguments;
			while (*tag_arguments && *tag_arguments != COLON )
				tag_arguments ++;
			if (*tag_arguments != COLON) {
				fprintf(stderr, "Bad input at PORT\n");
				exit(1);
			}
			port_end = tag_arguments - 1;

			tag_start = ++tag_arguments;
			while (*tag_arguments && *tag_arguments != COMMA )
				tag_arguments ++;
			if (*tag_arguments && *tag_arguments != COMMA) {
				fprintf(stderr, "Bad input at TAG\n");
				exit(1);
			}
			tag_end = tag_arguments - 1;

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
			if (!*tag_arguments)
				break;
		}

		if (!*tag_arguments)
			break;

		if (count == MAX_VIPS) {
			fprintf(stderr, "%s: Supports atmost %d vips\n",
				my_name, MAX_VIPS);
			exit(1);
		}

		tag_arguments ++;
	}

	pid_file = find_pid_file(remaining_args);
	*num_args = create_haproxy_args(total_args, remaining_args);

	return count;
}

int reread_config_file(void)
{
	static int first_time = 1;

	if (first_time) {
		first_time = 0;
		return 1;
	}

	action_taken = 0;
	if (my_filename) {
		/* Backup old arguments, and create new arguments */
		bcopy(vip_details, vip_details_old, sizeof(vip_details));
		total_vips_old = total_vips;

		/* And reset these */
		bzero(vip_details, sizeof(vip_details));
		total_vips = 0;

		/* Read the configuration again */
		total_vips = parse_file(my_filename, &num_haproxy_args);

		/* Validate that user has not giving any bad data */
		if (!validate_user_data()) {
			log_info("Bad duplicate tag");
			reload_status = 2;
			return 0;
		}

		/* Make sure old and new configurations are compatible */
		if (!validate_old_new_configs()) {
			log_info("New configuration not compatible with old");
			/* Restore earlier arguments */
			bcopy(vip_details_old, vip_details,
			      sizeof(vip_details));
			total_vips = total_vips_old;
			reload_status = 3;
			return 0;
		}

		log_info("New configuration is compatible with old");
		reload_status = 0;
	}

	reload_count++;

	return 1;
}

pthread_t create_thread(void *(*thread_handler) (void *), void *arg)
{
	pthread_t thread_id;
	pthread_attr_t attr;

	if (pthread_attr_init(&attr)) {
		perror("pthread_attr_init");
		return -1;
	}

	if (pthread_create(&thread_id, &attr, thread_handler, arg)) {
		perror("pthread_create");
		return -1;
	}

	pthread_attr_destroy(&attr);

	return thread_id;
}

int open_server_socket(void)
{
	struct sockaddr_in serv;
	int fd, set = 1;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv.sin_port = htons(RELOAD_PORT);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set));
	if (bind(fd, (struct sockaddr *)&serv, sizeof(struct sockaddr)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	listen(fd, 10);
	return fd;
}

void close_socket(int sockfd)
{
	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);
}

/* This thread accepts connection on port 25111, and sends last reload status */
static void *socket_command_handler(void *arg)
{
	int sockfd, ret = 0;
	int childfd;

	if ((sockfd = open_server_socket()) < 0) {
		/* No error handling required, all connect's will fail */
		return 0;
	}

	/* Need to close this thread on main program exit? */
	while (1) {
		int ret;
		struct sockaddr_in dest;
		socklen_t dlen = sizeof(dest);
		char buffer[1024];

		childfd = accept(sockfd, (struct sockaddr *)&dest, &dlen);
		if (childfd < 0) {
			perror("accept");
			continue;
		}

		sprintf(buffer, "Last reload-status: %d, reload-counter: %d\n",
			reload_status, reload_count);
		ret = write(childfd, &buffer, strlen(buffer));
		close_socket(childfd);

		sprintf(debug_str, "Sending reload status %d", reload_status);
		log_info(debug_str);
	}

	return 0;
}

void install_status_handler(void)
{
	pthread_t tid;

	tid = create_thread(&socket_command_handler, NULL);
	if (tid != -1)
		pthread_detach(tid);
}

void do_initial_setup(int argc, char *argv[])
{
	int i;

	if (my_filename) {
		total_vips = parse_file(my_filename, &num_haproxy_args);
		/* pid_file is already saved by parse_file() */
	} else {
		/*
		 * We were invoked as follows:
		 *	safe_reload <tags>    -f cfgfile -p pidfile
		 *      argv[0]     <argv[1]  other-args[2-..]
		 */
		total_vips = parse_cmdline_arguments(argc - 2, argv[1],
						     &argv[2],
						     &num_haproxy_args);
	}

	if (!total_vips) {
		log_info("No VIPs found");
		fprintf(stderr, "No VIPs found\n");
		exit(1);
	}

	if (!pid_file) {
		fprintf(stderr, "%s: -p <pid-file> is mandatory\n", argv[0]);
		exit(1);
	}

	enable_logging();

	if (!validate_user_data()) {
		log_info("Bad duplicate tag");
		fprintf(stderr, "Bad duplicate tag\n");
		exit(1);
	}

	log_info("Starting up");

	bcopy(vip_details, vip_details_old, sizeof(vip_details));
	total_vips_old = total_vips;
	action_taken = 1;

	signal(SIGUSR1, reload_handler);
	signal(SIGCHLD, child_handler);

	for (i = 0; i < total_vips; i++) {
		if (get_haproxy_socket(i))
			exit(1);
	}
}

void main(int argc, char *argv[])
{
	if (argc == 2) {
		my_filename = argv[1];
	} else if (argc < 6) {
		usage(argv[0]);
	} else if (argc - 1 > MAX_HAPROXY_ARGS) {
		fprintf(stderr, "%s: Maximum of %d arguments for haproxy\n",
			argv[0], MAX_HAPROXY_ARGS);
		exit(1);
	}

	my_name = argv[0];

	do_initial_setup(argc, argv);

#if 1
	if (daemon(1, 1)) {
		int ret;

		/* Failed to daemonize, do it ourselves */
		if ((ret = fork()) > 0) {
			/* Parent - exit */
			exit(0);
		} else if (ret < 0) {
			log_info("Unable to daemonize due to fork failure");
			exit(1);
		}

		/* Child -> Start a new session and continue */
		setsid();
	}
#endif

	install_status_handler();

	/*
	 * Wait till there is a signal from user to reload, or from a
	 * child that it has exited.
	 */
	while (1) {
		/* Check if we need configuration reload */
		if (reload_signal) {
			reload_status = 1;	/* Mark as error */
			if (reread_config_file())
				reload_signal_handler();
		}

		/* Check if we need to reap child */
		if (child_signal) {
			child_signal_handler();
		}

		/* Do nothing till another signal arrives */
		pause();
	}
}

/*
 * Combinations:
 *	New vip + port: Open socket, etc
 *	Same vip + port: Do nothing
 *	Vip + port is not present: Close socket
 * Validate vip + port is unique.
 * Validate each tag is unique.
 */

/*
Original file:
	ARGUMENTS -f haproxy.cfg -p /var/run/ha1/pid.file
	VIP 10.47.20.1
	PORT 80
	TAG FD1
	VIP 10.47.20.2
	PORT 443
	TAG FD2

Change to:
	ARGUMENTS -f haproxy.cfg -p /var/run/ha1/pid.file
	VIP 10.47.20.1
	PORT 80
	TAG FD1
	VIP 10.47.20.2
	PORT 443
	TAG FD2
	VIP 10.47.20.3
	PORT 80
	TAG FD3

Change to:
	ARGUMENTS -f haproxy.cfg -p /var/run/ha1/pid.file
	VIP 10.47.20.10
	PORT 80
	TAG FD1
	VIP 10.47.20.2
	PORT 443
	TAG FD2
	VIP 10.47.20.30
	PORT 80
	TAG FD3
	VIP 10.47.20.4
	PORT 80
	TAG FD4
*/
