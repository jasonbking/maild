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
#include "maild.h"
#include "local.h"
#include "log.h"

extern void client(int, char **);
extern void server(void);

int
main(int argc, char **argv)
{

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (getenv("SERVER") == NULL) {
		client(argc, argv);
		return (0);
	}

	server();
	return (0);
}
