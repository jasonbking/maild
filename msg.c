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
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <ctype.h>
#include <libnvpair.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <stdarg.h>
#include "maild.h"
#include "util.h"
#include "log.h"
#include "msg.h"

/*
 * A message is stored in multiple components.  The message itself is
 * stored in the queue directory named qf<random hex value>.  The metadata
 * of the message is stored as extended attributes:
 *
 * header	The header lines of the message
 * sender	The envelope sender address
 * env<nnn>	The envelope recipient, one per recipient
 */

#define	LINE_SZ		(1001)	/* 998 + CRLF + NULL per RFC 5322 */
#define RFC822DATE_LEN	(50)	/* should be big enough */
#define RFC822DATE_FMT  "%a, %d %b %Y %T %z"

#define	SENDER		"sender"
#define	HEADER		"header"
#define	ENVELOPE	"env"
#define	MSGID		"msgid"

static void msg_close(msg_t *);
static boolean_t msg_create_file(msg_t *, const char *);
static boolean_t msg_recv(msg_t *, int, int, boolean_t, boolean_t);
static boolean_t msg_set_name(msg_t *, int);
static boolean_t load_sender(msg_t *);
static boolean_t load_msgid(msg_t *);
static boolean_t load_envelopes(msg_t *);
static boolean_t save_sender(msg_t *);
static boolean_t save_msgid(msg_t *);
static boolean_t starts_with(const char *, const char *);
static char *msg_gen_id(const char *);
static void append_header(msg_t *, const char *, const char *, ...);

msg_t *
msg_new(const char *username, const char *sender, int in_fd, int timeout,
    boolean_t use_header, boolean_t ignore_dot)
{
	msg_t *msg = NULL;

	msg = zalloc(sizeof (*msg));
	msg->msg_sender = xstrdup(sender);

	if (!msg_create_file(msg, username))
		goto error;

	/* we should never end up with fd 0 as this */
	VERIFY3S(msg->msg_attrdir, >, 0);

	if (!msg_recv(msg, in_fd, timeout, use_header, ignore_dot))
		goto error;
	if (!save_msgid(msg))
		goto error;
	if (!msg_set_name(msg, spoolfd))
		goto error;

	return (msg);

error:
	msg_free(msg, B_TRUE);
	return (NULL);
}

static boolean_t
msg_set_name(msg_t *msg, int dir)
{
	char name[9];	/* large enough for a 32bit hex value */
	int fd = -1;

	/*
	 * the idea is generate a unique name and then rename the message
	 * to it
	 */

	do {
		(void) snprintf(name, sizeof (name), "%08" PRIx32, random32());
		fd = openat(dir, name, O_CREAT|O_RDWR|O_EXCL, 0600);
		if (fd == -1 && errno != EEXIST) {
			logmsg(LOG_ERR, "unable to rename queue file %s, "
			    "openat() failed: %m", msg->msg_filename);
			return (B_FALSE);
		}
	} while (fd < 0);

	if (renameat(dir, msg->msg_filename, dir, name) == -1) {
		logmsg(LOG_ERR, "unable to rename queue file %s, renameat "
		    "failed: %m", msg->msg_filename);
		(void) unlinkat(dir, name, 0);
		(void) close(fd);
		return (B_FALSE);
	}

	free(msg->msg_filename);
	msg->msg_filename = xstrdup(name);
	(void) close(fd);
	return (B_TRUE);
}

boolean_t
msg_open(int dirfd, msg_t *msg)
{
	if (msg->msg_f == NULL) {
		msg->msg_f = fopenat(dirfd, msg->msg_filename, "r");
		if (msg->msg_f == NULL)	{
			logmsg(LOG_ERR, "unable to open message %s: %m",
			    msg->msg_filename);
			goto fail;
		}
	}

	if (msg->msg_attrdir <= 0) {
		msg->msg_attrdir = openat(fileno(msg->msg_f), ".",
		    O_RDWR|O_XATTR);
		if (msg->msg_attrdir == -1) {
			logmsg(LOG_ERR, "unable to open extended attribute "
			    "dir of %s: %m", msg->msg_filename);
			goto fail;
		}
	}

	if (msg->msg_headerf == NULL) {
		msg->msg_headerf = fopenat(msg->msg_attrdir, HEADER, "r");
		if (msg->msg_headerf == NULL) {
			logmsg(LOG_ERR, "unable to open header attribute of "
			    "%s: %m", msg->msg_filename);
			goto fail;
		}
	}

	return (B_TRUE);

fail:
	msg_close(msg);
	return (B_FALSE);
}

/*
 * load a message with the given name in the directory dirfd
 * NOTE: none of the fields that refer to open fds (e.g. msg_f, etc) are
 * returned opened.
 */
msg_t *
msg_load(int dirfd, const char *name, boolean_t leave_open)
{
	msg_t *msg = zalloc(sizeof (*msg));
	DIR *d = NULL;
	struct dirent *de = NULL;
	int fd = -1;

	msg->msg_filename = xstrdup(name);

	if (!msg_open(dirfd, msg))
		goto fail;
	if (!load_sender(msg))
		goto fail;
	if (!load_msgid(msg))
		goto fail;
	if (!load_envelopes(msg))
		goto fail;

	if (!leave_open)
		msg_close(msg);
	return (msg);

fail:
	msg_free(msg, B_FALSE);
	return (NULL);
}

static boolean_t
load_envelopes(msg_t *msg)
{
	DIR *d = NULL;
	struct dirent *de = NULL;
	int fd = -1;

	/* fdopendir 'consumes' the fd, so use a copy */
	if ((fd = dup(msg->msg_attrdir)) == -1) {
		logmsg(LOG_ERR, "dup failed: %m");
		return (B_FALSE);
	}

	if ((d = fdopendir(fd)) == NULL) {
		logmsg(LOG_ERR, "fdopendir failed: %m");
		(void) close(fd);
		return (B_FALSE);
	}

	envelope_t *tail = NULL;
	while ((de = readdir(d)) != NULL) {
		FILE *envf = NULL;
		char line[LINE_SZ] = { 0 };
		uint32_t id = 0;

		if (!starts_with(de->d_name, ENVELOPE))
			continue;

		if (sscanf(de->d_name, ENVELOPE "%u", &id) <= 0) {
			logmsg(LOG_ERR, "message %s has corrupt envelope %s",
			    msg->msg_filename, de->d_name);
			goto fail;
		}

		envf = fopenat(msg->msg_attrdir, de->d_name, "r");
		if (envf == NULL) {
			logmsg(LOG_ERR, "unable to read envelope %s of %s: %m",
			    de->d_name, msg->msg_filename);
			goto fail;
		}

		if (fgets(line, sizeof (line) - 1, envf) == NULL) {
			logmsg(LOG_ERR, "corrupt envelope of message %s: %s",
			    msg->msg_filename,
			    feof(envf) ? "empty file" : strerror(errno));
			(void) fclose(envf);
			goto fail;
		}

		(void) fclose(envf);

		envelope_t *e = zalloc(sizeof (*e));
		e->env_to = xstrdup(line);
		e->env_id = id;

		if (tail != NULL)
			tail->env_next = e;
		else
			msg->msg_envelope = e;
		tail = e;
	}
	(void) closedir(d);
	return (B_TRUE);

fail:
	(void) closedir(d);
	return (B_FALSE);
}

static boolean_t
msg_create_file(msg_t *msg, const char *username)
{
	char filename[22] = { 0 };	/* .msg- + 16 hex + NULL */

	msg->msg_f = fmktempat(spoolfd, MSG_TEMP, &msg->msg_filename);
	if (msg->msg_f == NULL) {
		logmsg(LOG_ERR, "unable to create spool file: %m");
		return (B_FALSE);
	}

	msg->msg_attrdir = openat(fileno(msg->msg_f), ".", O_RDONLY|O_XATTR);
	if (msg->msg_attrdir == -1) {
		logmsg(LOG_ERR, "unable to read extended attributes: %m");
		return (B_FALSE);
	}

	msg->msg_headerf = fopenat(msg->msg_attrdir, HEADER, "w+x", 0600);
	if (msg->msg_headerf == NULL) {
		logmsg(LOG_ERR, "fdopen failed on header attribute: %m");
		return (B_FALSE);
	}

	append_header(msg, "Received",
	    "from %s (%s)\n"
	    "\tby %s (%s);\n"
	    "\t%s",
	    username, msg->msg_sender,
	    hostname, "maild",
	    rfc822_date());

	if (!save_sender(msg))
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
load_val(msg_t *msg, const char *name, char **valp)
{
	FILE *f = fopenat(msg->msg_attrdir, name, "r");
	char buf[LINE_SZ] = { 0 };
	boolean_t ret = B_TRUE;

	if (fgets(buf, sizeof (buf), f) == NULL) {
		logmsg(LOG_ERR, "unable to read %s attribute: %m", name);
		ret = B_FALSE;
	} else {
		*valp = xstrdup(buf);
	}
	(void) fclose(f);
	return (ret);
}

static boolean_t
load_sender(msg_t *msg)
{
	return (load_val(msg, SENDER, &msg->msg_from));
}

static boolean_t
load_msgid(msg_t *msg)
{
	return (load_val(msg, MSGID, &msg->msg_id));
}

static boolean_t
save_val(msg_t *msg, const char *name, const char *val)
{
	FILE *f = fopenat(msg->msg_attrdir, name, "w+x", 0600);
	size_t len = strlen(val);

	if (f == NULL) {
		logmsg(LOG_ERR, "unable to create the %s attribute: %m", name);
		return (B_FALSE);
	}
	if (fwrite(val, len, 1, f) != len)
		goto error;
	if (fputc('\n', f) != '\n')
		goto error;
	(void) fclose(f);
	return (B_TRUE);

error:
	logmsg(LOG_ERR, "error writing %s attribute value: %m", name);
	(void) fclose(f);
	(void) unlinkat(msg->msg_attrdir, name, 0);
	return (B_FALSE);
}

static boolean_t
save_sender(msg_t *msg)
{
	return (save_val(msg, SENDER, msg->msg_sender));
}

static boolean_t
save_msgid(msg_t *msg)
{
	return (save_val(msg, MSGID, msg->msg_id));
}

typedef struct line_state {
	char *addr_buf;
	size_t addr_len;
	size_t addr_alloc;
	boolean_t ignore_dot;
	boolean_t use_header;
	boolean_t is_addr;
	boolean_t body;
	boolean_t has_date;
	boolean_t has_from;
	boolean_t has_msgid;
	boolean_t skip;
} state_t;

static char *process_lines(msg_t *restrict, char *restrict, size_t,
    boolean_t *restrict, state_t *restrict);

/*
 * Save the incoming message from fd to the new spool file.  Transfer must
 * take less than timeout seconds to prevent tieing up the door
 * thread an indeterminate amount of time.
 */
static boolean_t
msg_recv(msg_t *msg, int fd, int timeout, boolean_t use_header,
    boolean_t ignore_dot)
{
	char buf[LINE_SZ] = { 0 };
	char *end = buf;
	size_t total = 0;
	ssize_t n = 0;
	time_t deadline;
	boolean_t ret = B_TRUE;
	boolean_t done = B_FALSE;
	state_t state = { 0 };

	state.ignore_dot = ignore_dot;
	state.use_header = use_header;

	if (fseeko(msg->msg_f, 0, SEEK_END) == -1) {
		logmsg(LOG_ERR, "unable to seek to end of message file: %m");
		return (B_FALSE);
	}
	if (fseeko(msg->msg_headerf, 0, SEEK_END) == -1) {
		logmsg(LOG_ERR, "unable to seek to end of header file: %m");
		return (B_FALSE);
	}

	deadline = time(NULL) + timeout;

	/*CONSTCOND*/
	while (!done) {
		size_t len = sizeof (buf) - 1 - (size_t)(end - buf);

		errno = 0;
		n = read_deadline(fd, end, len, deadline);
		if (n <= 0)
			break;

		if (total + n > max_msgsize) {
			errno = EFBIG;
			ret = B_FALSE;
			break;
		}
		total += n;

		/* buf should always be NULL terminated */
		ASSERT3S(buf[sizeof (buf) - 1], ==, '\0');

		end = process_lines(msg, buf, sizeof (buf), &done, &state);
		if (end == NULL) {
			ret = B_FALSE;
			break;
		}
	}

	if (n < 0 || process_lines(msg, buf, sizeof (buf), NULL,
	    &state) == NULL)
		ret = B_FALSE;

done:
	free(state.addr_buf);
	return (ret);
}

static boolean_t save_line(msg_t *restrict, char * restrict, size_t,
    state_t *restrict);
static boolean_t check_addrs(msg_t * restrict, char * restrict, size_t,
    state_t *restrict);

static char * 
process_lines(msg_t * restrict msg, char * restrict buf, size_t bufalloc,
    boolean_t * restrict donep, state_t *restrict statep)
{
	char *start, *end;
	size_t buflen = strlen(buf);
	size_t len;

	ASSERT3U(n, <, bufalloc);

	start = end = buf;

	if (donep == NULL) {
		if (buflen > 0) {
			if (buflen + 1 >= bufalloc) {
				errno = EOVERFLOW;
				return (NULL);
			}

			buf[buflen++] = '\n';
			if (!save_line(msg, buf, buflen, statep))
				return (NULL);
		}

		if (!save_line(msg, NULL, 0, statep))
			return (NULL);
	}

	while (1) {
		end = strchr(start, '\n');
		if (end == NULL)
			break;

		end++;
		len = (size_t)(end - start);

		if (!statep->ignore_dot && len == 2 && *start == '.') {
			if (donep != NULL)
				*donep = B_TRUE;
			*start = '\0';
			break;
		}

		if (!statep->body && len == 1 && *start == '\n') {
			statep->body = B_TRUE;
			start = end;

			if (statep->use_header
			    && !check_addrs(msg, NULL, 0, statep)) {
				return (NULL);
			}

			continue;
		}

		if (!save_line(msg, start, len, statep))
			return (NULL);

		if (statep->use_header && !statep->body
		    && !check_addrs(msg, start, len, statep))
			return (NULL);

		start = end;
	}

	if (*start == '\0') {
		/* no partial line, clear everything and reset */
		(void) memset(buf, 0, bufalloc);
		return (buf);
	}

	/* partial line at the start of the buffer */
	if (start == buf) {
		/* line too long */
		if (buflen + 1 == bufalloc) {
			errno = EOVERFLOW;
			return (NULL);
		}

		/* return end of current data */
		return (buf + buflen);
	}

	/* partial line, shift over */
	end = buf + buflen;
	len = (size_t)(end - start);

	/* I can actually read man pages */
	(void) memmove(buf, start, len);
	(void) memset(buf + len, 0, bufalloc - len);
	return (buf + len);
}

static boolean_t
save_line(msg_t *restrict msg, char *restrict line, size_t linesz,
    state_t *restrict st)
{
	if (line == NULL) {
		if (!st->has_msgid) {
			msg->msg_id = msg_gen_id(hostname);
			append_header(msg, "Message-Id", "<%s>", msg->msg_id);
		}
		if (!st->has_from)
			append_header(msg, "From", "<%s>", msg->msg_sender);
		if (!st->has_date)
			append_header(msg, "Date", "%s", rfc822_date());

		if (fflush(msg->msg_f) != 0) {
			logmsg(LOG_ERR, "fflush failed on message: %m");
			return (B_FALSE);
		}
		if (fflush(msg->msg_headerf) != 0) {
			logmsg(LOG_ERR, "fflush failed on message header: %m");
			return (B_FALSE);
		}

		return (B_TRUE);
	}

	if (st->body) {
		if (fwrite(line, linesz, 1, msg->msg_f) < 0) {
			logmsg(LOG_ERR, "error saving message body: %m");
			return (B_FALSE);
		}
		return (B_TRUE);
	}

	/* dealing with headers at this point */

	/* only reset skip (aka Bcc) on non-continuation lines */
	if (line[0] != ' ' && line[0] != '\t')
		st->skip = B_FALSE;

	/* rely on sizeof (line) > longest prefix to match */
	if (starts_with(line, "Date:")) {
		st->has_date = B_TRUE;
	} else if (starts_with(line, "From:")) {
		st->has_from = B_TRUE;
	} else if (starts_with(line, "Message-Id:")) {
		/* save off the msgid value */
		char *start = line + 11;
		char *end = NULL;

		while (start - line < linesz && *start != '<')
			start++;

		end = start + 1;
		while (end - line < linesz && *end != '>')
			end++;

		if (end - line < linesz && end - start > 1) {
			size_t len = (size_t)(end - start);

			msg->msg_id = zalloc(len + 1);
			(void) strncpy(msg->msg_id, start, len);
			st->has_msgid = B_TRUE;
		}
	} else if (starts_with(line, "Bcc:")) {
		st->skip = B_TRUE;
	}

	if (st->skip)
		return (B_TRUE);

	(void) fwrite(line, linesz, 1, msg->msg_headerf);
	return (B_TRUE);
}

static boolean_t
parse_addresses(msg_t *msg, const char *addrs)
{
	char *buf = NULL;
	char *p = NULL;
	size_t buflen = 0;
	int comment = 0;
	boolean_t quote = B_FALSE;
	boolean_t esc = B_FALSE;
	boolean_t bracket = B_FALSE;

	/*
	 * due to continuation lines, this could be > LINE_SZ, but can
	 * never be more than the source list
	 */
	buflen = strlen(addrs) + 1;
	buf = zalloc(buflen);

	/*
	 * Based on RFC5322, for our purposes, addresses can be viewed
	 * with a bit of pseudo notation:
	 *
	 * 	address := [ display_name ] < address >
	 * 	addresses := address [ (,|;)+ address ]
	 * 
	 * display_name may be empty (i.e. missing).  Both display_name
	 * and address can escape characters using a backslash and can
	 * use double quotes to enclose a portion of their value as well.
	 * In addition, comments can be included using parenthesis and
	 * can be nested to an arbitrary depth.
	 *
	 * To simplify parsing, we process the display name and then discard
	 * it in order to correctly locate the start of the address
	 */
	for (p = buf; *addrs != '\0'; addrs++) {
		if (esc) {
			esc = B_FALSE;
			if (*addrs == '\t' || *addrs == '\n')
				goto error;
			*p++ = *addrs;
			continue;
		}

		if (quote) {
			switch (*addrs) {
			case '"':
				quote = B_FALSE;
				break;
			case '\\':
				esc = B_TRUE;
				break;
			}
			*p++ = *addrs;
			continue;
		}

		if (comment > 0) {
			switch (*addrs) {
			case '(':
				comment++;
				break;
			case ')':
				if (--comment < 0) {
					/* XXX: msg */
					goto error;
				}
				break;
			}
			continue;
		}

		switch (*addrs) {
		case ' ':
		case '\t':
		case '\n':
			continue;

		case '(':
			comment++;
			continue;

		case ')':
			/* XXX: msg */
			goto error;

		case '<':
			bracket = B_TRUE;
			p = buf;
			*p = '\0';
			continue;

		case '>':
			if (!bracket)
				goto error;
			bracket = B_FALSE;

			if (p == buf)
				continue;

			*p++ = '\0';
			(void) msg_add_recipient(msg, buf);

			p = buf;
			*p = '\0';
			continue;

		case ':':
			p = buf;
			*p = '\0';
			continue;

		case ',':
		case ';':
			if (p == buf)
				continue;

			*p++ = '\0';
			if (!msg_add_recipient(msg, buf))
				goto error;

			p = buf;
			*p = '\0';
			continue;
		}

		*p++ = *addrs;
	}

	free(buf);
	return (B_TRUE);

error:
	free(buf);
	return (B_FALSE);
}

static boolean_t
check_addrs(msg_t * restrict msg, char * restrict line, size_t len,
    state_t * restrict st)
{
	if (line == NULL) {
		boolean_t ret = B_TRUE;

		if (st->addr_len > 0) {
			if (!parse_addresses(msg, st->addr_buf))
				ret = B_FALSE;
		}

		free(st->addr_buf);
		st->addr_buf = NULL;
		st->addr_len = st->addr_alloc = 0;
		return (ret);
	}

	if (line[0] == ' ' || line[0] == '\t') {
		if (!st->is_addr)
			return (B_TRUE);

		if (st->addr_len + len + 1 > st->addr_alloc) {
			size_t newlen = st->addr_alloc + LINE_SZ;

			st->addr_buf = xrealloc(st->addr_buf, newlen);
			st->addr_alloc = newlen;
		}
		strncat(st->addr_buf, line, len);
		st->addr_len += len;
		st->addr_buf[st->addr_len] = '\0';
		return (B_TRUE);
	}

	if (st->addr_len > 0) {
		if (!parse_addresses(msg, st->addr_buf))
			return (B_FALSE);
		(void) memset(st->addr_buf, 0, st->addr_alloc);
		st->addr_len = 0;
		st->is_addr = B_FALSE;
	}

	if (starts_with(line, "To:")
	    || starts_with(line, "Cc:")
	    || starts_with(line, "Bcc:")) {
		char *colon = strchr(line, ':');
		size_t addrsz = len - (size_t)(colon - line);

		if (st->addr_buf == NULL) {
			st->addr_buf = zalloc(LINE_SZ);
			st->addr_alloc = LINE_SZ;
		} else {
			(void) memset(st->addr_buf, 0, st->addr_alloc);
		}

		/*
		 * Since len <= LINE_SZ, addrsz <= LINE_SZ.
		 * Since st->addr_alloc >= LINE_SZ, this will always
		 * be NULL terminated
		 */
		(void) strncpy(st->addr_buf, colon + 1, addrsz);
		ASSERT3S(st->addr_buf[addrsz], ==, '\0');

		st->addr_len = addrsz;
		st->is_addr = B_TRUE;
	}
	return (B_TRUE);
}

boolean_t
msg_add_recipient(msg_t *msg, const char *to)
{
	FILE *envf = NULL;
	envelope_t *e = NULL;
	envelope_t *node = NULL;
	char name[14] = { 0 };
	uint32_t id = 0;

	node = msg->msg_envelope;
	while (node != NULL) {
		/* silently ignore duplicates */
		if (strcmp(node->env_to, to) == 0)
			return (B_TRUE);

		if (node->env_id > id)
			id = node->env_id + 1;
		if (node->env_next == NULL)
			break;
		node = node->env_next;
	}

	e = zalloc(sizeof (*e));
	e->env_to = xstrdup(to);
	e->env_id = id;

	(void) snprintf(name, sizeof (name), "env%u", id);
	envf = fopenat(msg->msg_attrdir, name, "w+x", 0600);
	if (envf == NULL) {
		logmsg(LOG_ERR, "unable to create envelope: %m");
		return (B_FALSE);
	}

	(void) fprintf(envf, "%s\n", to);
	if (ferror(envf) || fflush(envf) != 0) {
		logmsg(LOG_ERR, "unable to save envelope: %m");
		(void) fclose(envf);
		return (B_FALSE);
	}
	(void) fclose(envf);

	if (node != NULL)
		node->env_next = e;
	else
		msg->msg_envelope = e;

	return (B_TRUE);
}

static void
envelope_free(envelope_t *env)
{
	if (env == NULL)
		return;
	free(env->env_to);
	free(env);
}

static void
msg_close(msg_t *msg)
{
	if (msg->msg_headerf != NULL)
		(void) fclose(msg->msg_headerf);
	if (msg->msg_attrdir > 0)
		(void) close(msg->msg_attrdir);
	if (msg->msg_f != NULL)
		(void) fclose(msg->msg_f);

	msg->msg_f = msg->msg_headerf = NULL;
	msg->msg_attrdir = -1;
}

void
msg_free(msg_t *msg, boolean_t delete)
{
	boolean_t do_delete = B_FALSE;

	if (msg == NULL)
		return;

	if (msg->msg_f != NULL && delete)
		do_delete = B_TRUE;

	msg_close(msg);
	if (do_delete)
		(void) unlinkat(spoolfd, msg->msg_filename, 0);

	free(msg->msg_filename);
	free(msg->msg_sender);
	free(msg->msg_from);
	free(msg->msg_id);

	envelope_t *e = msg->msg_envelope;
	while (e != NULL) {
		envelope_t *next = e->env_next;

		envelope_free(e);
		e = next;
	}

	free(msg);
}

static void
to_base32(uint64_t val, char *buf, size_t buflen)
{
	/* 32 characters */
        static const char letters[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
	static const size_t letters_len = sizeof (letters) - 1;
	char *p = buf + buflen - 2;

	ASSERT3U(buflen, >=, 2);

	(void) memset(buf, 0, buflen);

	while (val > 0 && p >= buf) {
		*p-- = letters[val % letters_len];
		val /= letters_len;
	}

	/* zero-fill any remainder */
	while (p >= buf)
		*p-- = '0';
}

/* currently, the message id is <ms from epoch>.<random value>@hostname */
static char *
msg_gen_id(const char *hname)
{
	char *id = NULL;
        struct timeval tv = { 0 };
        uint64_t mstime = 0;
        uint64_t random_val = random64();
	char time_str[14] = { 0 };
	char rand_str[14] = { 0 };

        /* get time in milliseconds from epoch */
        VERIFY0(gettimeofday(&tv, NULL));
        mstime = tv.tv_sec * 1000 + tv.tv_usec / 1000;

	/* 64-bit value + . + 64bit value + @ + hostname + NULL */
	to_base32(mstime, time_str, sizeof (time_str));
	to_base32(random_val, rand_str, sizeof (rand_str));
	(void) asprintf(&id, "%s.%s@%s", time_str, rand_str, hname);

	return (id);
}

static void
append_header(msg_t *msg, const char *header, const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(msg->msg_headerf, "%s: ", header);
	va_start(ap, fmt);
	(void) vfprintf(msg->msg_headerf, fmt, ap);
	va_end(ap);
	(void) fputc('\n', msg->msg_headerf);
}

static boolean_t
starts_with(const char *s, const char *pfx)
{
        size_t pfxlen = strlen(pfx);

        if (strncasecmp(s, pfx, pfxlen) == 0)
                return (B_TRUE);
        return (B_FALSE);
}
