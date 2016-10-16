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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/debug.h>
#include <errno.h>
#include <err.h>
#include "aliases.h"
#include "log.h"

pthread_rwlock_t alias_lock = PTHREAD_RWLOCK_INITIALIZER;
alias_t *aliases = NULL;

static boolean_t add_alias_destinations(alias_t *restrict, char * restrict,
    size_t *restrict, size_t *restrict);
static void alias_free(alias_t *);

boolean_t
load_aliases(const char *filename)
{
	alias_t *new_alias = NULL;
	alias_t *tail = NULL;
	alias_t *curr = NULL;
	FILE *f = fopen(filename, "rF");
	char *line = NULL;
	size_t linenum = 0;
	size_t line_alloc = 0;
	size_t nalias = 0;
	size_t nalloc = 0;
	ssize_t linelen = 0;
	boolean_t success = B_FALSE;

	if (f == NULL) {
		logmsg(LOG_ERR, "unable to open alias file %s", filename);
		return (B_FALSE);
	}

	while ((linelen = getline(&line, &line_alloc, f)) != -1) {
		char *p = line;
		char *q = NULL;

		linenum++;

		if (*p == '#' || *p == '\0') {
			curr = NULL;
			nalias = nalloc = 0;
			continue;
		}

		if (isspace(*p)) {
			if (curr == NULL) {
				/* XXX: error */
				continue;
			}

			/* continuation */
			while (*p != '\0' && isspace(*p))
				p++;

			/* XXX: return value */
			add_alias_destinations(curr, p, &nalias, &nalloc);
			continue;
		}

		q = strchr(p, ':');
		if (q == NULL) {
			logmsg(LOG_ERR, "invalid entry on line %zu in %s; "
			    "skipping", linenum, filename);
			continue;
		}

		/* split line at colon */
		*q++ = '\0';

		curr = malloc(sizeof (alias_t));
		if (curr == NULL)
			err(EXIT_FAILURE, "out of memory");
		nalias = nalloc = 0;

		if (!add_alias_destinations(curr, p, &nalias, &nalloc)) {
			/* XXX: msg? */
			alias_free(curr);
			continue;
		}

		if (tail == NULL) {
			new_alias = tail = curr;
		} else {
			tail->next = curr;
			tail = curr;
		}
	}

	if (ferror(f)) {
		logmsg(LOG_ERR, "error reading %s: %m", filename);
		success = B_FALSE;
	}
	(void) fclose(f);

	if (!success) {
		alias_free(aliases);
		return (B_FALSE);
	}

	alias_t *old = NULL;

	VERIFY0(pthread_rwlock_wrlock(&alias_lock));
	old = aliases;
	aliases = new_alias;
	VERIFY0(pthread_rwlock_unlock(&alias_lock));

	alias_free(old);
	return (B_TRUE);
}

#define	CHUNK_SZ (4)
static boolean_t
add_alias_dest(alias_t *restrict alias, const char *restrict dest,
    size_t *restrict n, size_t *restrict alloc)
{
	if (*n + 1 >= *alloc) {
		size_t new_alloc = *alloc + CHUNK_SZ;
		size_t new_size = new_alloc * sizeof (char *);
		char **temp = NULL;

		if (new_size / sizeof (char *) != new_alloc) {
			errno = EOVERFLOW;
			return (B_FALSE);
		}

		temp = realloc(alias->addresses, new_size);
		if (temp == NULL)
			return (B_FALSE);

		alias->addresses = temp;
		*alloc = new_alloc;
	}

	if ((alias->addresses[*n] = strdup(dest)) == NULL)
		return (B_FALSE);

	(*n)++;

	return (B_TRUE);
}

static boolean_t
add_alias_destinations(alias_t *restrict ap, char * restrict destinations,
    size_t *restrict n, size_t *restrict alloc)
{
	char *p = NULL;
	char *lasts = NULL;

	for (p = strtok_r(destinations, ",", &lasts);
	    p != NULL;
	    p = strtok_r(NULL, ",", &lasts)) {
		size_t len = strlen(p);
		char *end = p + len - 1;

		while (*p != '\0' && isspace(*p))
			p++;

		while (end > p && isspace(*end))
			end--;

		end[1] = '\0';

		/* XXX: warn on overflow? */
		if (!add_alias_dest(ap, p, n, alloc))
			return (B_FALSE);
	}

	return (B_TRUE);
}

static void
alias_free(alias_t *aliases)
{
	while (aliases != NULL) {
		alias_t *next = aliases->next;

		free(aliases->alias);

		for (int i = 0; aliases->addresses[i] != NULL; i++)
			free(aliases->addresses[i]);
		free(aliases->addresses);

		free(aliases);
		aliases = next;
	}
}
