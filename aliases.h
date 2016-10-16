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

#ifndef _ALIASES_H
#define	_ALIASES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <sys/types.h>

struct alias;
typedef struct alias alias_t;

struct alias {
	alias_t	*next;
	char	*alias;
	char	**addresses;
};

extern pthread_rwlock_t alias_lock;
extern alias_t *aliases;

boolean_t load_aliases(const char *);

#ifdef __cplusplus
}
#endif

#endif /* _ALIASES_H */
