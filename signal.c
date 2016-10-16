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

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <err.h>
#include <sys/debug.h>
#include <string.h>
#include <port.h>
#include "log.h"
#include "maild.h"

static void *
signal_handler(void *ptr_port)
{
	sigset_t sigset;
	int	port;
	int	signo;
	int	ret;

	port = (int)(uintptr_t)ptr_port;

	logmsg(LOG_DEBUG, "signal thread awaiting signals");

	(void) sigfillset(&sigset);

	/*CONSTCOND*/
	for (;;) {
		char buf[SIG2STR_MAX];

		if (sigwait(&sigset, &signo) != 0) {
			logmsg(LOG_INFO, "sigwait error: %m");
			continue;
		}

		(void) memset(buf, 0, sizeof (buf));
		sig2str(signo, buf);
		logmsg(LOG_DEBUG, "caught SIG%s", buf);

		ret = port_send(port, EVENT_SIGNAL, (void *)signo);
		if (ret == -1)
			logmsg(LOG_ERR, "port_send failed: %m");
	}

	/*NOTREACHED*/
	return (NULL);
}

void
signal_init(int port)
{
	pthread_attr_t attr;
	pthread_t tid;
	sigset_t nset;
	int ret;

	/* Block all signals in main thread */
	(void) sigfillset(&nset);
	(void) pthread_sigmask(SIG_SETMASK, &nset, NULL);

	ret = pthread_attr_init(&attr);
	if (ret != 0)
		errx(EXIT_FAILURE, "pthread_attr_init failed: %s",
		    strerror(ret));

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0)
		errx(EXIT_FAILURE, "pthread_attr_setdetachstate failed: %s",
		    strerror(ret));

	ret = pthread_create(&tid, &attr, signal_handler,
	    (void *)(uintptr_t)port);

	if (ret != 0)
		errx(EXIT_FAILURE, "pthread_create(signal_handler) failed: %s",
		    strerror(ret));

	logmsg(LOG_DEBUG, "Created signal handler");
}

