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

#ifndef _MSG_H
#define	_MSG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdio.h>

struct envelope;
typedef struct envelope envelope_t;

struct msg;
typedef struct msg msg_t;

struct envelope {
        envelope_t      *env_next;
        char            *env_to;
        uint32_t        env_id;
};

struct msg {
        msg_t           *msg_next;
        char            *msg_id;
        char            *msg_from;
        char            *msg_sender;
        envelope_t      *msg_envelope;
        char            *msg_filename;
        FILE            *msg_f;
        FILE            *msg_headerf;
        int             msg_attrdir;
};

msg_t *msg_new(const char *, const char *, int, int, boolean_t, boolean_t);
msg_t *msg_load(int, const char *, boolean_t);
boolean_t msg_open(int, msg_t *);
boolean_t msg_add_recipient(msg_t *, const char *);
void msg_free(msg_t *, boolean_t);

#ifdef __cplusplus
}
#endif

#endif /* _MSG_H */
