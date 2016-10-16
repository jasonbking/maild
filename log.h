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

#ifndef _LOG_H
#define	_LOG_H

#include <sys/types.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_log(const char *, boolean_t);
void logmsg(int, const char *, ...);

#ifdef __cplusplus
}
#endif

#endif /* _LOG_H */
