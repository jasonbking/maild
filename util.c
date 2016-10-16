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

#include <sys/stat.h>
#include <sys/debug.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>
#include <pwd.h>
#include <time.h>
#include "util.h"

static pthread_once_t random_once = PTHREAD_ONCE_INIT;
static int random_fd = -1;

void *
zalloc(size_t amt)
{
	void *p = calloc(1, amt);

	if (p == NULL)
		err(EXIT_FAILURE, "out of memory");

	return (p);
}

void *
xrealloc(void *p, size_t newlen)
{
	char *newp = realloc(p, newlen);

	if (newp == NULL)
		err(EXIT_FAILURE, "out of memory");

	return (newp);
}

char *
xstrdup(const char *s)
{
	char *dest = strdup(s);

	if (dest == NULL)
		err(EXIT_FAILURE, "out of memory");
	return (dest);
}

static void
init_random(void)
{
	if ((random_fd = open("/dev/urandom", O_RDONLY)) == -1)
		err(EXIT_FAILURE, "unable to open /dev/urandom");
}

uint32_t
random32(void)
{
	uint32_t val = 0;

	VERIFY0(pthread_once(&random_once, init_random));
	(void) read(random_fd, &val, sizeof (val));
	return (val);
}

uint64_t
random64(void)
{
	uint64_t val = 0;

	VERIFY0(pthread_once(&random_once, init_random));
	(void) read(random_fd, &val, sizeof (val));
	return (val);
}

/* fopen : open :: fopenat : openat */
FILE *
fopenat(int atfd, const char *name, const char *modestr, ...)
{
	FILE *f = NULL;
	int fd = -1;
	int flags = 0;
	va_list ap;

	switch (modestr[0]) {
	case 'r':
		flags = O_RDONLY;
		break;
	case 'w':
		flags = O_WRONLY|O_TRUNC|O_CREAT;
		break;
	case 'a':
		flags = O_WRONLY|O_TRUNC|O_CREAT;
		break;
	default:
		errno = EINVAL;
		return (NULL);
	}

	for (const char *flg = modestr + 1; *flg != '\0'; flg++) {
		switch (*flg) {
		case '+':
			flags = (flags & ~(O_RDONLY|O_WRONLY)) | O_RDWR;
			break;
		case 'e':
			flags |= O_CLOEXEC;
			break;
		case 'x':
			flags |= O_EXCL;
			break;
		default:
			/* ignore anything else */
			;
		}
	}

	va_start(ap, modestr);
	mode_t modeval = va_arg(ap, mode_t);
	va_end(ap);

	if ((fd = openat(atfd, name, flags, modeval)) == -1)
		return (NULL);

	/*
	 * NOTE: This could potentially leave a stale file if the openat
	 * succeeds but the fdopen fails.  However, for how we're using this
	 * it shouldn't present a problem.
	 */
	if ((f = fdopen(fd, modestr)) == NULL) {
		(void) close(fd);
		return (NULL);
	}

	return (f);
}

FILE *
fmktempat(int fd, const char *prefix, char **filenamep)
{
	FILE *f = NULL;
	char *filename = NULL;
	size_t len = 0;

	len = strlen(prefix);
	filename = zalloc(len + 8 + 1);	/* 8 hex digits + NULL */

	while (1) {
		(void) snprintf(filename, len, "%s%0" PRIx32, prefix,
		    random32());

		if ((f = fopenat(fd, filename, "w+x", 0600)) != NULL)
			break;

		if (errno != EEXIST) {
			free(filename);
			return (NULL);
		}
	}

	if (filenamep != NULL)
		*filenamep = filename;

	return (f);
}

/*
 * Read from a file descriptor, waiting upto deadline time as passed.
 * Return the number of bytes read, or -1 on error.
 * If deadline has passed, return -1 and set errno to ETIMEDOUT
 */
ssize_t
read_deadline(int fd, void *buf, size_t len, time_t deadline)
{
        struct pollfd fds = {
                .fd = fd,
                .events = POLLIN
        };
        time_t now = time(NULL);
        int nfd = -1;

        if (now >= deadline) {
                errno = ETIMEDOUT;
                return (-1);
        }

        nfd = poll(&fds, 1, deadline - now);
        if (nfd == -1) {
                return (-1);
        } else if (nfd == 0) {
                errno = ETIMEDOUT;
                return (-1);
        }

        VERIFY3S(nfd, ==, 1);

        return (read(fd, buf, len));
}

/* assumes fileno(f) has been set nonblocking */
boolean_t
read_line_deadline(FILE *f, char *buf, size_t buflen, time_t deadline)
{
	char *p = buf;
	time_t now = time(NULL);

	if (now > deadline)
		goto toolate;

	while ((size_t)(p - buf) < buflen) {
		int c = fgetc(f);

		if (c != EOF) {
			*p++ = c;
			if (c == '\n')
				break;

			continue;
		}

		if (errno != EAGAIN)
			return (B_FALSE);

		struct pollfd fds = {
			.fd = fileno(f),
			.events = POLLIN
		};

		if (time(&now) > deadline)
			goto toolate;

		int nfd = poll(&fds, 1, deadline - now);

		if (nfd == -1)
			return (B_FALSE);
		if (nfd == 0)
			goto toolate;
	}

	return (B_TRUE);

toolate:
	errno = ETIMEDOUT;
	return (B_FALSE);
}

const char *
get_username(uid_t uid)
{
	static const char unknown[] = "unknown";
	static pthread_key_t username_key = PTHREAD_ONCE_KEY_NP;
	char *name = NULL;
	struct passwd *pw = NULL;

	if (uid == (uid_t)-1)
		return (unknown);

	VERIFY0(pthread_key_create_once_np(&username_key, free));
	if ((name = pthread_getspecific(username_key)) == NULL) {
		name = zalloc(LOGNAME_MAX + 1);
		VERIFY0(pthread_setspecific(username_key, name));
	}

	pw = getpwuid(uid);
	if (pw != NULL)
		(void) strlcpy(name, pw->pw_name, LOGNAME_MAX + 1);
	else
		(void) snprintf(name, LOGNAME_MAX + 1, "uid %d", uid);

	return (name);
}

#define	DATE_FMT "%a, %d %b %Y %T %z"
#define	DATE_LEN 50
const char *
rfc822_date(void)
{
	static pthread_key_t rfc822_date_key = PTHREAD_ONCE_KEY_NP;
	char *str = NULL;
	time_t now;

	VERIFY0(pthread_key_create_once_np(&rfc822_date_key, free));
	if ((str = pthread_getspecific(rfc822_date_key)) == NULL) {
		str = zalloc(DATE_LEN);
		VERIFY0(pthread_setspecific(rfc822_date_key, str));
	}

	now = time(NULL);
	(void) strftime(str, DATE_LEN - 1, DATE_FMT, localtime(&now));
	return (str);
}

boolean_t
set_nonblock(FILE *f, boolean_t set)
{
	int fd = fileno(f);
	int flags = 0;

	if ((flags = fcntl(fd, F_GETFD, 0)) < 0)
		return (B_FALSE);

	if (set)
		flags |= O_NONBLOCK;
	else 
		flags &= ~(O_NONBLOCK);

	if (fcntl(fd, F_SETFD, flags) < 0)
		return (B_FALSE);

	return (B_TRUE);
}
