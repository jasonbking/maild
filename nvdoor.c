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
#include <sys/debug.h>
#include <stdlib.h>
#include <door.h>
#include <alloca.h>
#include <err.h>
#include "maild.h"

/*
 * Handy functions for passing nvlists back and forth across a door call.
 */

boolean_t
nvdoor_call(int door, nvlist_t * restrict nvl, int * restrict fds, size_t n,
    boolean_t free_nvl)
{
	char		*buf = NULL;
	size_t		buflen = 0;
	door_arg_t	darg = { 0 };
	door_desc_t	*ddesc = NULL;
	int		ret;

	ASSERT((fds == NULL && n == 0) || (fds != NULL && n > 0));

	if (nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_NATIVE, 0) != 0)
		return (B_FALSE);

	darg.data_ptr = buf;
	darg.data_size = buflen;
	if (n > 0) {
		ddesc = calloc(n, sizeof (door_desc_t));
		if (ddesc == NULL)
			return (B_FALSE);
		for (size_t i = 0; i < n; i++) {
			ddesc[i].d_attributes = DOOR_DESCRIPTOR;
			ddesc[i].d_data.d_desc.d_descriptor = fds[i];
		}
		darg.desc_ptr = ddesc;
		darg.desc_num = n;
	} else {
		darg.desc_ptr = NULL;
		darg.desc_num = 0;
	}

	ret = door_call(door, &darg);

	free(ddesc);
	free(buf);
	if (free_nvl)
		nvlist_free(nvl);

	return ((ret == 0) ? B_TRUE : B_FALSE);
}

/* 
 * NOTE: As the resulting packed nvlist must be allocated on the stack
 * (*sigh*), callers must ensure there is sufficient space on the stack
 * for the resulting nvlist.  In practice, the size of the nvlists are
 * rather small that this is not an issue.
 */
boolean_t
nvdoor_return(nvlist_t * restrict nvl, int * restrict fds, size_t n,
    boolean_t free_nvl)
{
	door_desc_t *ddesc = NULL;
	char *buf = NULL;
	size_t buflen = 0;

	if (nvl != NULL) {
		buflen = fnvlist_size(nvl);
		buf = alloca(buflen);

		/* can't use fnvlist_pack because it allocates memory */
		if (nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_NATIVE, 0) != 0)
			err(EXIT_FAILURE, "unable to pack nvlist");
	}

	if (n > 0) {
		ddesc = alloca(n * sizeof (door_desc_t));
		for (size_t i = 0; i < n; i++) {
			ddesc[i].d_attributes = DOOR_DESCRIPTOR;
			ddesc[i].d_data.d_desc.d_descriptor = fds[i];
		}
	}

	if (free_nvl)
		nvlist_free(nvl);

	(void) door_return(buf, buflen, ddesc, n);

	return (B_FALSE);
}

