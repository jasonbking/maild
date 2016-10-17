/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Jason King
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/debug.h>
#include <door.h>
#include <atomic.h>
#include <libnvpair.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <stdio.h>
#include <stropts.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <port.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <netdb.h>
#include <dirent.h>
#include "maild.h"
#include "msg.h"
#include "local.h"
#include "log.h"
#include "util.h"

/* config defaults */
char *maild_doorpath = "/var/run/maild";
char *smarthost = NULL;
char *spooldir = "/var/spool/maild";
char *aliasfile = "/etc/mail/aliases";
char *masquerade_host = NULL;
char *masquerade_user = NULL;
char *hostname = NULL;
boolean_t local_delivery = B_TRUE;

int maild_door = -1;
int spoolfd = -1;

/* how long we take to receive a message from a client */
static int client_timeout = 10;

/* maximum number of outstanding door calls before we start punting */
static uint_t max_clients = 100;
static volatile uint_t client_count;

/* maximum number of items that can be queued */
static size_t max_queuesize = 1000;

/* how long we wait to receive a message */
static int read_timeout = 30;

/* maximum message size */
size_t max_msgsize = 10 * 1024 * 1024;

/*
 * Currently only the main thread listening on the event port manipulates
 * these.  If multiple threads are added for the event port loop, a mutex
 * will need to be added.
 */
static msg_t *msg_head;
static msg_t *msg_tail;

static timer_t queue_timer;
static volatile boolean_t stop = B_FALSE;

static void server_loop(void);
static void server_signal(int);
static void server_door_create(void);
static void server_door_handler(void *, char *, size_t, door_desc_t *, uint_t);
static boolean_t server_newmsg(nvlist_t *, const ucred_t *, int, nvlist_t *);
static boolean_t server_deliver_msg(msg_t *);
static void server_defer_msg(msg_t *);
static void server_load_queue(void);
static void client_return_err(void);
static void server_return_resp(nvlist_t *);
static void init_hostname(void);
static void init_timer(int);

void
server(void)
{
	(void) setlocale(LC_ALL, "");

	printf("starting server...\n");

	if (getenv("SPOOL") != NULL)
		spooldir = getenv("SPOOL");

	init_hostname();

	if ((spoolfd = open(spooldir, O_RDONLY)) == -1)
		err(EXIT_FAILURE, "unable to read %s", spooldir);
#if 0
	if (chdir("/") == -1)
		err(EXIT_FAILURE, "unable to chdir to /");
#endif

	evport = port_create();
	if (evport == -1)
		err(EXIT_FAILURE, "port_create() failed");

	init_timer(evport);
	init_log("maild", B_TRUE);
	signal_init(evport);
	server_door_create();

	if (local_delivery) {
		if (!local_start("/tmp/maild", "mail", 10))
			errx(EXIT_FAILURE, "timeout waiting for local "
			    "delivery process to start");
	}

	server_load_queue();

	/*
	 * we created the door, but delay attaching it to the filesystem
	 * until here so that we can be sure the local delivery process
	 * has successfully started (if enabled) before accepting client
	 * requests
	 */
	(void) fdetach(maild_doorpath);
	if (fattach(maild_door, maild_doorpath) < 0)
		err(EXIT_FAILURE, "cannot attach to door");

	/* XXX: try to deliver if anything remaining */

	server_loop();

	(void) fdetach(maild_doorpath);
	(void) door_revoke(maild_door);
	(void) unlink(maild_doorpath);
}

static void
server_loop(void)
{
	printf("Waiting for requests\n");

	while (!stop) {
		port_event_t pe = { 0 };
		msg_t *msg = NULL;
		int ret = -1;

		ret = port_get(evport, &pe, NULL);
		if (ret != 0) {
			/* this hsould be the only error we ever get */
			if (errno != ETIME)
				err(EXIT_FAILURE, "port_get() failed");

			/* XXX handle timeout */
			continue;
		}

		switch (pe.portev_source) {
		case PORT_SOURCE_USER:
			break;
		case PORT_SOURCE_TIMER:
			/* XXX */
			break;
		case PORT_SOURCE_FILE:
			/* XXX */
			break;
		default:
			logmsg(LOG_CRIT, "unexpected event source %d",
			    pe.portev_source);
			VERIFY(0);
		}

		switch (pe.portev_events) {
		case EVENT_SIGNAL:
			server_signal((int)pe.portev_user);
			break;

		case EVENT_NEWMSG:
			msg = (msg_t *)pe.portev_user;

			if (server_deliver_msg(msg))
				msg_free(msg, B_TRUE);
			else
				server_defer_msg(msg);

			break;

		case EVENT_DEFERMSG:
			msg = (msg_t *)pe.portev_user;
			server_defer_msg(msg);
			break;

		default:
			logmsg(LOG_CRIT, "unexpected user event %d",
			    pe.portev_events);
			VERIFY(0);
		}
	}
}

static void
server_door_create(void)
{
	struct stat sb = { 0 };
	int fd = -1;

	maild_door = door_create(server_door_handler, 0, 0);
	if (maild_door == -1)
		err(EXIT_FAILURE, "door_create() failed");

	if (stat(maild_doorpath, &sb) == 0) {
		if ((sb.st_mode & S_IAMB) != 0644
		    || sb.st_uid != getuid()
		    || sb.st_gid != getgid())
			errx(EXIT_FAILURE, "%s has invalid permissions",
			    maild_doorpath);
	} else {
		if (errno != ENOENT)
			err(EXIT_FAILURE, "Error accessing %s", maild_doorpath);

		fd = open(maild_doorpath, O_WRONLY|O_CREAT, 0644);
		if (fd == -1)
			err(EXIT_FAILURE, "cannot create door file");
		(void) close(fd);
	}
}

static void
server_door_handler(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc)
{
	nvlist_t *req = NULL;
	nvlist_t *resp = NULL;
	ucred_t *uc = NULL;
	uint32_t val = 0;

	if (atomic_inc_uint_nv(&client_count) > max_clients) {
		logmsg(LOG_INFO, "too many connections");
		goto fail;
	}

	if (door_ucred(&uc) != 0) {
		logmsg(LOG_ERR, "door_ucred failed: %m");
		goto fail;
	}

	resp = fnvlist_alloc();

	nvlist_unpack(argp, arg_size, &req, NULL);

	(void) printf("request from pid %d\n", ucred_getpid(uc));
	nvlist_print(stdout, req);

	if (nvlist_lookup_uint32(req, MAILD_NVCMD, &val) != 0) {
		logmsg(LOG_INFO, "received nvlist with missing cmd from "
		    "pid %d uid %d", ucred_getpid(uc), ucred_getruid(uc));
		goto fail;
	}

	switch (val) {
	case MAILD_SUBMIT:
		server_newmsg(req, uc, dp[0].d_data.d_desc.d_descriptor, resp);
		break;
	case MAILD_LIST_QUEUE:
		break;
	case MAILD_RUN_QUEUE:
		break;
	case MAILD_INIT_LOCAL:
		if (ucred_getpid(uc) != local_getpid()) {
			logmsg(LOG_WARNING, "received MAILD_INIT_LOCAL "
			    "from non-child pid %d uid %d",
			    ucred_getpid(uc), ucred_getruid(uc));
			goto fail;
		}

		VERIFY3U(n_desc, ==, 1);
		local_startup_complete(dp[0].d_data.d_desc.d_descriptor);
		goto done;

	default:
		logmsg(LOG_INFO, "received invalid command number %u from "
		    "pid %d uid %d", ucred_getpid(uc), ucred_getruid(uc));
		goto fail;
	}

done:
	ucred_free(uc);
	nvlist_free(req);
	server_return_resp(resp);

fail:
	nvlist_free(req);
	nvlist_free(resp);
	ucred_free(uc);
	client_return_err();
}

static void
server_signal(int sig)
{
	switch (sig) {
	case SIGCHLD:
		err(EXIT_FAILURE, "local delivery process exited");
		break;
	case SIGINT:
		(void) printf("Exiting on SIGINT\n");
		local_stop();
		stop = B_TRUE;
	}
}

static boolean_t
server_newmsg(nvlist_t *req, const ucred_t *uc, int fd, nvlist_t *resp)
{
	const char *username = NULL;
	msg_t *msg = NULL;
	char *from = NULL;
	char **to = NULL;
	size_t n_to = 0;
	int ret = 0;
	boolean_t use_header;
	boolean_t defer;
	boolean_t ignore_dot;

	username = get_username(ucred_getruid(uc));

	(void) nvlist_lookup_string(req, MAILD_NVSENDER, &from);
	(void) nvlist_lookup_string_array(req, MAILD_NVTO, &to, &n_to);
	ret |= nvlist_lookup_boolean_value(req, MAILD_NVHEADER, &use_header);
	ret |= nvlist_lookup_boolean_value(req, MAILD_NVDEFER, &defer);
	ret |= nvlist_lookup_boolean_value(req, MAILD_NVDOTS, &ignore_dot);
	/*
	 * the client code shouldn't trigger these, however since anyone
	 * is free to invoke the door, still need verification
	 */
	if (ret != 0) {
		logmsg(LOG_ERR, "invalid request (missing data in nvlist) "
		    "from %s pid %d", username, ucred_getpid(uc));

		fnvlist_add_uint32(resp, MAILD_NVRESP, MAILD_INVAL);
		return (B_FALSE);
	}
	if (!use_header && (from == NULL || n_to == 0)) {
		logmsg(LOG_ERR, "invalid request (from or to address missing)"
		    "from %s pid %d", username, ucred_getpid(uc));
		fnvlist_add_uint32(resp, MAILD_NVRESP, MAILD_INVAL);
		return (B_FALSE);
	}

	msg = msg_new(username, from, fd, client_timeout, use_header,
	    ignore_dot);
	if (msg == NULL) {
		switch (errno) {
		case EFBIG:
			ret = MAILD_TOOBIG;
			break;
		case EOVERFLOW:
			ret = MAILD_LINE;
			break;
		case ETIMEDOUT:
			ret = MAILD_TIMEOUT;
			break;
		default:
			ret = MAILD_FAILURE;
		}

		fnvlist_add_uint32(resp, MAILD_NVRESP, ret);
		return (B_FALSE);
	}

	for (size_t i = 0; i < n_to; i++) {
		if (!msg_add_recipient(msg, to[i])) {
			msg_free(msg, B_TRUE);
			fnvlist_add_uint32(resp, MAILD_NVRESP, MAILD_FAILURE);
			return (B_FALSE);
		}
	}

	char *id = xstrdup(msg->msg_id);

	/*
	 * while unlikely, using msg->msg_id after the port_send could
	 * result in a use after free if for some reason the message
	 * was able to be delivered before we add it to the response
	 * nvlist, so a copy is used
	 */
	VERIFY0(port_send(evport, (defer) ? EVENT_DEFERMSG : EVENT_NEWMSG,
	    msg));

	fnvlist_add_uint32(resp, MAILD_NVRESP, MAILD_SUCCESS);
	fnvlist_add_string(resp, MAILD_NVID, id);
	free(id);

	return (B_TRUE);
}

static boolean_t
server_deliver_msg(msg_t *msg)
{
	/* XXX temp */
	msg_free(msg, B_FALSE);
	return (B_FALSE);
}

static void
server_defer_msg(msg_t *msg)
{
	(void) fclose(msg->msg_f);
	(void) fclose(msg->msg_headerf);
	msg->msg_f = NULL;
	msg->msg_headerf = NULL;

	if (msg_tail == NULL) {
		msg_head = msg_tail = msg;
		return;
	}
	msg_tail->msg_next = msg;
	msg_tail = msg;
}

static void
server_load_queue(void)
{
	DIR *d = NULL;
	struct dirent *de = NULL;
	int fd = dup(spoolfd);

	VERIFY3S(fd, >, 0);
	VERIFY3P(d = fdopendir(fd), !=, NULL);

	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;

		/* remove any incomplete messages */
		if (strncmp(de->d_name, MSG_TEMP, sizeof (MSG_TEMP)) == 0) {
			if (unlinkat(spoolfd, de->d_name, 0) < 0)
				logmsg(LOG_ERR, "unlinkat(%s) failed: %m",
				    de->d_name);
			continue;
		}

		msg_t *msg = msg_load(spoolfd, de->d_name, B_FALSE);
		if (msg == NULL)
			continue;

		if (msg_tail == NULL) {
			msg_head = msg_tail = msg;
		} else {
			msg_tail->msg_next = msg;
			msg_tail = msg;
		}
	}

	closedir(d);
}

static void
client_return_err(void)
{
	nvlist_t *resp = fnvlist_alloc();

	fnvlist_add_uint32(resp, MAILD_NVRESP, MAILD_FAILURE);
	atomic_dec_uint(&client_count);
	(void) nvdoor_return(resp, NULL, 0, B_TRUE);
}

static void
server_return_resp(nvlist_t *resp)
{
	atomic_dec_uint(&client_count);
	(void) nvdoor_return(resp, NULL, 0, B_TRUE);
}

static void
init_hostname(void)
{
	if (masquerade_host != NULL) {
		hostname = strdup(masquerade_host);
		return;
	}

	hostname = zalloc(MAXHOSTNAMELEN + 1);
	VERIFY0(gethostname(hostname, MAXHOSTNAMELEN));
}

static void
init_timer(int port)
{
	struct sigevent sigev = { 0 };
	port_notify_t pn = { 0 };

	pn.portnfy_port = port;
	pn.portnfy_user = NULL;
	sigev.sigev_notify = SIGEV_PORT;
	sigev.sigev_value.sival_ptr = &pn;

	if (timer_create(CLOCK_REALTIME, &sigev, &queue_timer) < 0)
		err(EXIT_FAILURE, "timer_create() failed");
}
