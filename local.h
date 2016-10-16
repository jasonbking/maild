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

#ifndef _LOCAL_H
#define	_LOCAL_H /* bound for the floor? */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

boolean_t local_delivermsg(const char *, const char *, int);
boolean_t local_start(const char *, const char *, int);
void local_startup_complete(int);
void local_stop(void);
pid_t local_getpid(void);

#ifdef __cplusplus
}
#endif

#endif /* _LOCAL_H */
