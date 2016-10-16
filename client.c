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
#include <pthread.h>
#include <unistd.h>
#include <libnvpair.h>
#include <stdio.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include "maild.h"

/*
 * All the code in client.c runs with as the invoking user
 */

struct send_opts {
	const char	*sender;
	boolean_t	ignore_dot;
	boolean_t	defer;
	boolean_t	use_header;
};

static boolean_t client_show_queue(void);
static boolean_t client_run_queue(void);
static int client_sendmsg(struct send_opts, char * const *);
static int client_door_call(nvlist_t * restrict, int * restrict, size_t);

void
client(int argc, char **argv)
{
	char *sender = NULL;
	int c;
	boolean_t opt_show_queue = B_FALSE;
	boolean_t opt_defer_email = B_FALSE;
	boolean_t opt_ignore_dot = B_FALSE;
	boolean_t opt_run_queue = B_FALSE;
	boolean_t opt_use_header = B_FALSE;
	boolean_t error = B_FALSE;
	boolean_t ret;

	while ((c = getopt(argc, argv, ":A:b:f:iOo:q:r:t")) != -1) {
		switch (c) {
		case 'A':
			if (optarg[0] != 'c')
				error = B_TRUE;
			break;
		case 'b':
			switch (optarg[0]) {
			case 'p':
				opt_show_queue = B_TRUE;
				break;
			case 'q':
				opt_defer_email = B_TRUE;
				break;
			default:
				error = B_TRUE;
			}
			break;
		case 'f':
		case 'r':
			sender = optarg;
			break;
		case 'i':
			opt_ignore_dot = B_TRUE;
			break;
		case 'O':
			/* ignored */
			break;
		case 'o':
			switch (optarg[0]) {
			case 'i':
				opt_ignore_dot = B_TRUE;
				break;
			default:
				error = B_TRUE;
			}
			break;
		case 'q':
			/* ignore argument */
			opt_run_queue = B_TRUE;
			break;
		case 't':
			opt_use_header = B_TRUE;
			break;
		case '?':
			error = B_TRUE;
			break;
		case ':':
			errx(EXIT_FAILURE, "-%c option is missing argument",
			    optopt);
		}
		if (error) {
			(void) fprintf(stderr, "Usage: %s stuff here...\n",
			    argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* XXX: mutual exclusive option check */

	if (opt_show_queue)
		ret = client_show_queue();
	else if (opt_run_queue)
		ret = client_run_queue();
	else 
		ret = client_sendmsg((struct send_opts){
		    .sender = sender,
		    .ignore_dot = opt_ignore_dot,
		    .defer = opt_defer_email,
		    .use_header = opt_use_header},
		    &argv[optind]);

	if (!ret)
		exit(EXIT_FAILURE);
}

static boolean_t
client_show_queue(void)
{
	nvlist_t *req = fnvlist_alloc();
	int outfd = STDOUT_FILENO;
	int ret;

	fnvlist_add_uint32(req, MAILD_NVCMD, (uint32_t)MAILD_LIST_QUEUE);

	/* just to be safe, make sure nothing is waiting to be written out */
	(void) fflush(stdout);
	ret = client_door_call(req, &outfd, 1);
	if (ret != 0) {
		/* XXX: translate ret value to error message */
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
client_run_queue(void)
{
	nvlist_t *req = fnvlist_alloc();
	int ret;

	fnvlist_add_uint32(req, MAILD_NVCMD, (uint32_t)MAILD_RUN_QUEUE);
	ret = client_door_call(req, NULL, 0);
	if (ret != 0) {
		/* XXX error message */
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
client_sendmsg(struct send_opts opts, char * const *recipients)
{
	nvlist_t *req;
	int fd = STDIN_FILENO;
	int ret;

	req = fnvlist_alloc();
	fnvlist_add_uint32(req, MAILD_NVCMD, (uint32_t)MAILD_SUBMIT);
	if (opts.sender != NULL)
		fnvlist_add_string(req, MAILD_NVSENDER, opts.sender);
	if (recipients != NULL) {
		size_t n_to = 0;

		for (n_to = 0; recipients[n_to] != NULL; n_to++)
			;
		if (n_to > 0)
			fnvlist_add_string_array(req, MAILD_NVTO, recipients,
			    n_to);
	}
	fnvlist_add_boolean_value(req, MAILD_NVDEFER, opts.defer);
	fnvlist_add_boolean_value(req, MAILD_NVHEADER, opts.use_header);
	fnvlist_add_boolean_value(req, MAILD_NVDOTS, opts.ignore_dot);

	ret = client_door_call(req, &fd, 1);

	if (ret != 0) {
		/* XXX: error */
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
client_door_call(nvlist_t * restrict req, int * restrict fds, size_t n)
{
	int fd, rc;
	int count = 0;

	/*
	 * in case the client is invoked while the server is restarting,
	 * pause and retry on certain failures
	 */
again:
	fd = open(maild_doorpath, O_RDONLY);
	if (fd == -1) {
		if (errno == EEXIST && count < 10) {
			sleep(1);
			count++;
			goto again;
		}
		err(EXIT_FAILURE, "unable to open %s", maild_doorpath);
	}

	rc = nvdoor_call(fd, req, fds, n, B_TRUE);
	if (rc == -1) {
		if (errno == EAGAIN || errno == EBADF && count < 10) {
			sleep(1);
			count++;
			(void) close(fd);
			goto again;
		}
	}
	(void) close(fd);
}
