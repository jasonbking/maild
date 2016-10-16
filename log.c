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
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "log.h"

static boolean_t is_debug = B_FALSE;

void
init_log(const char *name, boolean_t dbg)
{
	is_debug = dbg;
	if (dbg)
		return;

	openlog(name, LOG_PID|LOG_NDELAY, LOG_MAIL);
}

static void debugmsg(const char *, va_list);

void
logmsg(int pri, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);

	if (is_debug)
		debugmsg(msg, ap);
	else
		vsyslog(pri, msg, ap);

	va_end(ap);
}

typedef struct str {
	char *s;
	size_t len;
	size_t alloc;
} str_t;

#define	CHUNK	(128)
static void
appendc(str_t *s, int c)
{
	if (s->len + 2 >= s->alloc) {
		s->alloc += CHUNK;
		s->s = xrealloc(s->s, s->alloc);
	}
	s->s[s->len++] = c;
	s->s[s->len] = '\0';
}

static void
appendstr(str_t *s, const char *val)
{
	size_t len = strlen(val);

	if (s->len + len + 1 > s->alloc) {
		s->alloc += len + CHUNK;
		s->s = xrealloc(s->s, s->alloc);
	}
	(void) strlcat(s->s, val, s->alloc);
}

static void
debugmsg(const char *msg, va_list ap)
{
	str_t s = { 0 };
	int errsave = errno;

	for (size_t i = 0; msg[i] != '\0'; i++) {
		if (msg[i] != '%') {
			appendc(&s, msg[i]);
			continue;
		}

		if (msg[i + 1] != 'm') {
			appendc(&s, '%');
			appendc(&s, msg[++i]);
			continue;
		}

		const char *errmsg = strerror(errsave);

		if (errmsg != NULL) {
			appendstr(&s, errmsg);
			i++;
			continue;
		}

		/* 'error ' + maxlen(int) + NULL */
		char buf[6 + 10 + 1];
		(void) snprintf(buf, sizeof (buf), "error %d", errsave);
		appendstr(&s, buf);
		i++;
	}

	/* XXX: should this be stderr instead? */
	(void) vfprintf(stdout, s.s, ap);
	(void) fputc('\n', stdout);

	free(s.s);
}

