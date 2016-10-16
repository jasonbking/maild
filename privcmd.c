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

#include <sys/debug.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <priv.h>
#include <unistd.h>

#define	V(x)	VERIFY((x) == 0)

int
pc_open(const char *path, int oflag, mode_t mode)
{
	int errsave;
	int fd;

	if (oflag & O_RDONLY|O_RDWR)
		V(priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_FILE_READ, NULL));
	if (oflag & O_WRONLY|O_RDWR)
		V(priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_FILE_WRITE, NULL));

	if (oflag & O_CREAT)
		fd = open(path, oflag, mode);
	else
		fd = open(path, oflag);

	if (fd == -1)
		errsave = errno;

	if (oflag & O_WRONLY|O_RDWR)
		V(priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_FILE_WRITE, NULL));
	if (oflag & O_RDONLY|O_RDWR)
		V(priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_FILE_READ, NULL));

	if (fd == -1)
		errno = errsave;
	return (fd);
}

int
pc_fchown(int fd, uid_t uid, gid_t gid)
{
	int ret, errsave;

	V(priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_FILE_CHOWN, NULL));
	ret = fchown(fd, uid, gid);
	if (ret == -1)
		errsave = errno;
	V(priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_FILE_CHOWN, NULL));

	if (ret == -1)
		errno = errsave;
	return (ret);
}


