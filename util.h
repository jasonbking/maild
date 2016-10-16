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

#ifndef _UTIL_H
#define	_UTIL_H

#include <stdio.h>
#include <inttypes.h>
#include <time.h>

void *zalloc(size_t);
void *xrealloc(void *, size_t);
char *xstrdup(const char *);
uint32_t random32(void);
uint64_t random64(void);
FILE *fopenat(int, const char *, const char *, ...);
FILE *fmktempat(int, const char *, char **);
ssize_t read_deadline(int, void *, size_t, time_t);
boolean_t read_line_deadline(FILE *, char *, size_t, time_t);
const char *get_username(uid_t);
const char *rfc822_date(void);
boolean_t set_nonblock(FILE *, boolean_t);

#endif /* _UTIL_H */
