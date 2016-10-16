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

#ifndef _MAILD_H
#define _MAILD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/queue.h>
#include <sys/types.h>
#include <libintl.h>
#include <libnvpair.h>
#include <stdio.h>

#define	_(x)	gettext(x)

#define	MAILD_NVCMD	"command"
#define	MAILD_NVSENDER	"sender"
#define	MAILD_NVTO	"to"
#define	MAILD_NVDOTS	"ignore-dots"
#define	MAILD_NVDEFER	"defer"
#define	MAILD_NVHEADER	"use-header"

#define	MSG_TEMP	".msg-"

typedef enum mailcmd {
	MAILD_SUBMIT,
	MAILD_LIST_QUEUE,
	MAILD_RUN_QUEUE,
	MAILD_INIT_LOCAL
} mailcmd_t;

typedef enum mailresp {
	MAILD_SUCCESS,
	MAILD_FAILURE,
	MAILD_TIMEOUT,
	MAILD_TOOBIG
} mailresp_t;

#define	EVENT_SIGNAL	(1)
#define	EVENT_LOCALFD	(2)
#define	EVENT_NEWMSG	(3)
#define	EVENT_DEFERMSG	(4)

extern char *maild_doorpath;
extern char *smarthost;
extern char *spooldir;
extern char *aliasfile;
extern char *masquerade_host;
extern char *masquerade_user;
extern char *hostname;

extern size_t max_msgsize;
extern int maild_door;
extern int evport;
extern int spoolfd;

boolean_t nvdoor_call(int, nvlist_t * _RESTRICT_KYWD, int * _RESTRICT_KYWD,
    size_t, boolean_t);
boolean_t nvdoor_return(nvlist_t * _RESTRICT_KYWD, int * _RESTRICT_KYWD,
    size_t, boolean_t);
void signal_init(int);

#ifdef __cplusplus
}
#endif

#endif /* _MAILD_H */
