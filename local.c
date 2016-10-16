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
#include <sys/stat.h>
#include <sys/debug.h>
#include <synch.h>
#include <stdlib.h>
#include <stdio.h>
#include <door.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <priv.h>
#include <syslog.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <libnvpair.h>
#include <ucred.h>
#include <port.h>
#include <signal.h>
#include <pthread.h>
#include "maild.h"
#include "log.h"
#include "privcmd.h"

/*
 * The local delivery agent.  A separate process is used to segregate the
 * necessary elevated privileges needed for mailbox delivery.  Currently this
 * is only needed when creating new mailboxes.
 *
 * Delivery requests come from the mail daemon via a door that is currently
 * only shared between the two daemons.  Privilege bracketing is used to
 * further restict privileges (including privileges in the basic set) to
 * only the necessary sections of code for extra paranoia.
 */

#define	LOCK_ATTEMPTS	(10)
#define	LOCK_SLEEP	(10L * 1000L); /* in ns */
#define	LINESZ		(1024)

#define	NV_CMD		"command"
#define	CMD_DELIVER	"deliver"
#define	NV_USER		"user"
#define	NV_FROM		"from"
#define	NV_RESULT	"result"

static void drop_privs(void);
static void local_door_handler(void *, char *, size_t, door_desc_t *, uint_t);
static boolean_t local_wait_for_startup(int);
static boolean_t deliver_mail(const char *, const char *, int);
static int open_mbox(const char *);
static void local_signal(int);

static const char *mailpath;
static gid_t mail_gid;
static pthread_mutex_t local_start_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t local_start_cv = PTHREAD_COND_INITIALIZER;

static int local_door = -1;
static volatile pid_t local_pid = 0;

boolean_t
local_delivermsg(const char *from, const char *to, int msgfd)
{
	nvlist_t	*cmd = NULL;
	int		ret;

	if (nvlist_alloc(&cmd, NV_UNIQUE_NAME, 0) != 0)
		return (B_FALSE);

	ret = 0;
	ret |= nvlist_add_string(cmd, NV_CMD, CMD_DELIVER);
	ret |= nvlist_add_string(cmd, NV_USER, to);
	ret |= nvlist_add_string(cmd, NV_FROM, from);
	if (ret != 0) {
		nvlist_free(cmd);
		return (B_FALSE);
	}

	if (!nvdoor_call(local_door, cmd, &msgfd, 1, B_TRUE))
		return (B_FALSE);
	return (B_TRUE);
}

boolean_t
local_start(const char *mpath, const char *mailgrp, int timeout)
{
	struct group *grp = NULL;
	nvlist_t *nvl = NULL;
	int ret;
	boolean_t done = B_FALSE;

	mailpath = mpath;

	grp = getgrnam(mailgrp);
	if (grp == NULL) {
		(void) fprintf(stderr, "mail group %s not found\n", mailgrp);
		return (B_FALSE);
	}

	mail_gid = grp->gr_gid;

	VERIFY0(pthread_mutex_lock(&local_start_mtx));

	local_pid = fork();
	if (local_pid == (pid_t)-1)
		err(EXIT_FAILURE, "unable to create local delivery process");

	if (local_pid > 0)
		return (local_wait_for_startup(timeout));

	drop_privs();

	/* this makes sense if you squint hard enough */
	if (dup2(maild_door, STDIN_FILENO) == -1)
		err(EXIT_FAILURE, "dup2 failed");
	maild_door = STDIN_FILENO;

	closefrom(STDERR_FILENO + 1);

	local_door = door_create(local_door_handler, NULL, 0);
	if (local_door == -1)
		err(EXIT_FAILURE, "door_create failed");

	init_log("mail.local", B_FALSE);

	/* openlog may open files, so turn these off after */
	priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_FILE_READ, NULL);
	priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_FILE_CHOWN, NULL);
	priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_FILE_WRITE, NULL);

	/* lastly, send our doorfd back to maild */
	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, MAILD_NVCMD, (uint32_t)MAILD_INIT_LOCAL);
	if (!nvdoor_call(maild_door, nvl, &local_door, 1, B_TRUE))
		exit(1);

	nvlist_free(nvl);
	nvl = NULL;

	evport = port_create();
	if (evport == -1)
		err(EXIT_FAILURE, "unable to create event port");

	signal_init(evport);

	while (!done) {
		port_event_t pe = { 0 };

		ret = port_get(evport, &pe, NULL);
		if (ret == -1)
			err(EXIT_FAILURE, "port_get failed");

		switch (pe.portev_events) {
		case EVENT_SIGNAL:
			local_signal((int)pe.portev_user);
			break;
		}
		/* XXX: stuff here */
	}

	exit(0);
}

static boolean_t
local_wait_for_startup(int timeout)
{
	struct timespec ts = {
		.tv_sec = timeout,
		.tv_nsec = 0
	};
	int ret;

	VERIFY(MUTEX_HELD(&local_start_mtx));

	ret = pthread_cond_reltimedwait_np(&local_start_cv, &local_start_mtx,
	    &ts);
	if (ret == ETIMEDOUT)
		return (B_FALSE);
	if (ret != 0)
		errx(EXIT_FAILURE, "pthread_cond_reltimedwait_np failed: %s",
		    strerror(errno));
	return (B_TRUE);
}

void
local_startup_complete(int fd)
{
	local_door = fd;
	VERIFY0(pthread_cond_signal(&local_start_cv));
}

void
local_stop(void)
{
	kill(local_pid, SIGKILL);
}

static void
local_door_handler(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t ndesc)
{
	nvlist_t *nvl = NULL;
	char *cmd = NULL;
	ucred_t *uc = NULL;
	struct passwd *pw = NULL;
	const char *username = NULL;
	uid_t uid;
	pid_t pid;

	if (door_ucred(&uc) != 0)
		err(EXIT_FAILURE, "door_ucred() failed");

	uid = ucred_getruid(uc);
	pid = ucred_getpid(uc);
	ucred_free(uc);

	pw = getpwuid(uid);
	if (pw != NULL)
		username = pw->pw_name;
	else
		username = "(unknown)";

	if (nvlist_unpack(argp, arg_size, &nvl, 0) != 0) {
		logmsg(LOG_WARNING, "received invalid nvlist from pid %d "
		    "user %s (uid %d)", pid, username, uid);
		goto done;
	}

	if (nvlist_lookup_string(nvl, NV_CMD, &cmd) != 0) {
		logmsg(LOG_WARNING, "nvlist from pid %d user %s (uid %d) ",
		    "is missing the command parameter", pid, username, uid);
		goto done;
	}

	if (strcmp(cmd, CMD_DELIVER) != 0) {
		char *from = NULL;
		char *to = NULL;
		int ret = 0;

		/* from could be empty if from MAILER-DAEMON */
		(void) nvlist_lookup_string(nvl, NV_FROM, &from);
		ret |= nvlist_lookup_string(nvl, NV_USER, &to);
		if (ret != 0) {
			logmsg(LOG_WARNING, "nvlist from pid %d user %s uid %d "
			    "is missing to address", pid, username, uid);
			goto done;
		}
		deliver_mail(to, from, dp->d_data.d_desc.d_descriptor);
	} else {
		logmsg(LOG_WARNING, "unkonwn command '%s' received from pid %d "
		    "user %s uid %d", cmd, pid, username, uid);
	}

done:
	nvlist_free(nvl);
	door_return(NULL, 0, NULL, 0);
}

static boolean_t
deliver_mail(const char *user, const char *from, int fd)
{
	FILE *inf = NULL;
	FILE *outf = NULL;
	struct stat sb = { 0 };
	char line[LINESZ];
	off_t mboxlen = 0;
	int mboxfd = -1;
	boolean_t nl;

	logmsg(LOG_DEBUG, "deliver mail from %s to %s", from, user);

	if (fstat(fd, &sb) < 0) {
		logmsg(LOG_ERR, "unable to stat(2) fd from maild: %m");
		(void) close(fd);
		return (B_FALSE);
	}

	if (!S_ISREG(sb.st_mode)) {
		logmsg(LOG_ERR, "received unexpected fd type 0x%04x "
		    "from maild", (int)(sb.st_mode & S_IFMT));
		(void) close(fd);
		return (B_FALSE);
	}

	if ((inf = fdopen(fd, "r")) == NULL) {
		logmsg(LOG_ERR, "unable to fdopen queued email: %m");
		(void) close(fd);
		return (B_FALSE);
	}

	mboxfd = open_mbox(user);
	if (mboxfd == -1) {
		(void) fclose(inf);
		return (B_FALSE);
	}

	if ((outf = fdopen(mboxfd, "a+")) == NULL) {
		logmsg(LOG_ERR, "unable to fdopen mailbox: %m");
		goto fail;
	}

	time_t now = time(NULL);
	(void) fprintf(outf, "\nFrom %s %s\n", from, ctime(&now));

	nl = B_FALSE;
	while (!feof(inf) && !ferror(outf)) {
		size_t len = 0;

		(void) memset(line, 0, sizeof (line));

		if (fgets(line, sizeof (line), inf) == NULL)
			break;

		len = strlen(line);

		if (nl) {
			size_t gt = strspn(line, ">");

			if (strncmp(&line[gt], "From ", 5) == 0)
				(void) fputc('>', outf);
		} else if (len == 1 && line[0] == '\n') {
			nl = B_TRUE;
		} else {
			nl = B_FALSE;
		}


		(void) fwrite(line, len, 1, outf);
	}

	if (ferror(outf))
		goto fail;

	(void) fflush(outf);
	(void) lockf(mboxfd, F_ULOCK, 0);
	(void) fclose(outf);
	(void) fclose(inf);
	return (B_TRUE);

fail:
	if (inf != NULL)
		(void) fclose(inf);
	else
		(void) close(fd);

	if (outf != NULL) {
		(void) fflush(outf);
		(void) ftruncate(mboxfd, mboxlen);
	}
	if (mboxfd > -1)
		(void) lockf(mboxfd, F_ULOCK, 0);
	if (outf != NULL)
		(void) fclose(outf);

	return (B_FALSE);
}

static int
open_mbox(const char *user)
{
	char *path = NULL;
	struct passwd *pwd = NULL;
	int fd = -1;
	int ret;
	boolean_t created = B_FALSE;
	
	logmsg(LOG_NOTICE, "creating mailbox for %s", user);

	if (strchr(user, '/') != NULL) {
		logmsg(LOG_ERR, "User %s contains / in name", user);
		return (B_FALSE);
	}

	pwd = getpwnam(user);
	if (pwd == NULL)
		goto bail;

	/* only reason this can fail is out of memory */
	if (asprintf(&path, "%s/%s", mailpath, user) == -1)
		err(EXIT_FAILURE, "unable to create mailbox path");

	fd = pc_open(path, O_RDWR|O_EXCL|O_CREAT|O_NOFOLLOW, 0600);
	if (fd == -1) {
		if (errno != EEXIST)
			goto bail;

		/*
		 * there is a chance something could delete the mbox
		 * between the first open attempt failing and this.
		 * if this happens, we just punt and let maild queue and
		 * retry later
		 */
		fd = pc_open(path, O_RDWR|O_NOFOLLOW);
		if (fd == -1)
			goto bail;
	} else {
		created = B_TRUE;
	}
	free(path);
	path = NULL;

	for (int i = 0; i < LOCK_ATTEMPTS; i++) {
		struct timespec ts = { 0 };

		ret = lockf(fd, F_TLOCK, 0);
		if (ret == 0)
			break;

		switch (errno) {
		case EACCES:
		case EAGAIN:
			ts.tv_sec = 0;
			ts.tv_nsec = LOCK_SLEEP;
			(void) nanosleep(&ts, NULL);
			continue;
		default:
			goto bail;
		}
	}

	if (ret != 0)
		goto bail;

	if (lseek(fd, SEEK_END, 0) == (off_t)-1)
		goto bail;

	/* defer changing permissions on create to ensure we get the lock */
	if (created) {
		ret = fchmod(fd, 0620);
		if (ret < 0) 
			goto bail;

		pc_fchown(fd, pwd->pw_uid, mail_gid);
		if (ret < 0)
			goto bail;
	}

	return (fd);

bail:
	logmsg(LOG_ERR, "Unable to create mailbox for %s: %s", user,
	    strerror(errno));

	if (fd >= 0) {
		(void) lockf(fd, F_ULOCK, 0);
		(void) close(fd);
	}
	free(path);
	return (-1);
}

static void
drop_privs(void)
{
	priv_set_t *ps = priv_str_to_set("basic", ",", NULL);

	if (ps == NULL)
		err(EXIT_FAILURE, "unable to allocate privilege set");

	(void) priv_addset(ps, PRIV_FILE_CHOWN);

	(void) priv_delset(ps, PRIV_PROC_EXEC);
	(void) priv_delset(ps, PRIV_PROC_FORK);
	(void) priv_delset(ps, PRIV_NET_ACCESS);

	(void) priv_inverse(ps);
	(void) setppriv(PRIV_OFF, PRIV_PERMITTED, ps);
	(void) setppriv(PRIV_OFF, PRIV_LIMIT, ps);

	priv_freeset(ps);
}

static void
local_signal(int sig)
{
	switch (sig) {
	case SIGINT:
		(void) printf("locald Exiting on SIGINT\n");
		exit(1);
	}
}

pid_t
local_getpid(void)
{
	return (local_pid);
}
