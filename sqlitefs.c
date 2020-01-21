/*
 *  Copyright (C) 2018-2020 Gaël PORTAY
 *                2018      Savoir-Faire Linux Inc.
 *
 *  SPDX-License-Identifier: LGPL-2.1
 */

#define FUSE_USE_VERSION 34

#ifdef HAVE_CONFIG_H
# include "config.h"
#else
const char PACKAGE_VERSION[] = __DATE__ " " __TIME__;
#endif /* HAVE_CONFIG_H */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>

#include <libgen.h>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include <sqlite3.h>
#include <pthread.h>

#include <linux/limits.h>
#include <linux/fs.h>

#include "hexdump.h"

static int DEBUG = 0;
#define debug(fmt, ...) if (DEBUG) fprintf(stderr, fmt, ##__VA_ARGS__)
#define debug2(fmt, ...) if (DEBUG >= 2) fprintf(stderr, fmt, ##__VA_ARGS__)
#define hexdebug(addr, buf, size) if (DEBUG) fhexdump(stderr, addr, buf, size)
#define hexdebug2(addr, buf, size) if (DEBUG >= 2) fhexdump(stderr, addr, buf, size)

#define __min(a,b) ({ \
	__typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a < _b ? _a : _b; \
})

#define __max(a,b) ({ \
	__typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a > _b ? _a : _b; \
})

#define __strncmp(s1, s2) strncmp(s1, s2, sizeof(s2) - 1)

#define __return(s) do {\
	perror(s); \
	return -errno; \
} while (0)

#define __exit(s) do {\
	perror(s); \
	exit(EXIT_FAILURE); \
} while (0)

#define __return_perror(s, e) do { \
	fprintf(stderr, "%s: %s\n", s, strerror(e)); \
	return -e; \
} while (0)

#define __exit_perror(s, e) do {\
	fprintf(stderr, "%s: %s\n", s, strerror(e)); \
	exit(EXIT_FAILURE); \
} while (0)

#define __perror(s, e) do { \
	fprintf(stderr, "%s: %s\n", s, strerror(e)); \
} while (0)

#define __data(s) s, sizeof(s) - 1

#define __sqlite3_perror(s, db) do { \
	fprintf(stderr, "%s: %s\n", s, sqlite3_errmsg(db)); \
} while (0)

static const char *mode_r(mode_t mode, char *buf, size_t bufsize)
{
	if (S_ISREG(mode))
		return strncpy(buf, "regular file", bufsize);

	if (S_ISDIR(mode))
		return strncpy(buf, "directory", bufsize);

	if (S_ISBLK(mode))
		return strncpy(buf, "block special file", bufsize);

	if (S_ISCHR(mode))
		return strncpy(buf, "character special file", bufsize);

	if (S_ISFIFO(mode))
		return strncpy(buf, "fifo", bufsize);

	if (S_ISLNK(mode))
		return strncpy(buf, "symbolic link", bufsize);

	if (S_ISSOCK(mode))
		return strncpy(buf, "socket", bufsize);

	return strncpy(buf, "unknown", bufsize);
}

static const char *uid_r(const uid_t uid, char *buf, size_t bufsize)
{
	const char *name = "unknown";
	char pwdbuf[BUFSIZ];
	struct passwd *pwds;
	struct passwd pwd;

	if (getpwuid_r(uid, &pwd, pwdbuf, sizeof(pwdbuf), &pwds) == 0)
		name = pwd.pw_name;

	snprintf(buf, bufsize, "%5i/%8s", uid, name);

	return buf;
}

static const char *gid_r(const gid_t gid, char *buf, size_t bufsize)
{
	const char *name = "unknown";
	char grpbuf[BUFSIZ];
	struct group *grps;
	struct group grp;

	if (getgrgid_r(gid, &grp, grpbuf, sizeof(grpbuf), &grps) == 0)
		name = grp.gr_name;

	snprintf(buf, bufsize, "%5i/%8s", gid, name);

	return buf;
}

static const char *timespec_r(const struct timespec *ts, char *buf,
			      size_t bufsize)
{
	struct tm tm;
	size_t n;

	if (!localtime_r(&ts->tv_sec, &tm))
		return NULL;

	n = strftime(buf, bufsize, "%Y-%m-%d %H:%M:%S", &tm);
	if (!n)
		return NULL;

	if (n < bufsize)
		snprintf(buf+n, bufsize-n, ".%09li", ts->tv_nsec);

	return buf;
}

static int fprintstat(FILE *f, const char *path, const struct stat *buf)
{
	char atimbuf[BUFSIZ];
	char mtimbuf[BUFSIZ];
	char ctimbuf[BUFSIZ];
	char modebuf[BUFSIZ];
	char gidbuf[BUFSIZ];
	char uidbuf[BUFSIZ];

	return fprintf(f, "  File: %s\n"
			  "  Size: %li\tBlocks: %li\tIO Block: %li\t%s\n"
			  "Device: %lx/%li\tInode: %lu\tLinks: %li\n"
			  "Access: (O%04o)\tUid: (%s)\tGid: (%s)\n"
			  "Access: %s\n"
			  "Modify: %s\n"
			  "Change: %s\n"
			  " Birth: -\n",
			  path, buf->st_size, buf->st_blocks, buf->st_blksize, mode_r(buf->st_mode, modebuf, sizeof(modebuf)),
			  buf->st_rdev, buf->st_rdev, buf->st_ino, buf->st_nlink,
			  buf->st_mode, uid_r(buf->st_uid, uidbuf, sizeof(uidbuf)), gid_r(buf->st_gid, gidbuf, sizeof(gidbuf)),
			  timespec_r(&buf->st_atim, atimbuf, sizeof(atimbuf)),
			  timespec_r(&buf->st_mtim, mtimbuf, sizeof(mtimbuf)),
			  timespec_r(&buf->st_ctim, ctimbuf, sizeof(ctimbuf)));
}

struct getattr_data {
	int error;
	struct stat *st;
};

static int getattr_cb(void *data, int argc, char **argv, char **colname)
{
	struct getattr_data *pdata = (struct getattr_data *)data;
	int i;
	(void)argc;
	(void)colname;

	i = 1;
	pdata->error = 0;
	pdata->st->st_dev = strtol(argv[i++], NULL, 0);
	pdata->st->st_ino = strtol(argv[i++], NULL, 0);
	pdata->st->st_mode = strtol(argv[i++], NULL, 0);
	pdata->st->st_nlink = strtol(argv[i++], NULL, 0);
	pdata->st->st_uid = strtol(argv[i++], NULL, 0);
	pdata->st->st_gid = strtol(argv[i++], NULL, 0);
	pdata->st->st_rdev = strtol(argv[i++], NULL, 0);
	pdata->st->st_size = strtol(argv[i++], NULL, 0);
	pdata->st->st_blksize = strtol(argv[i++], NULL, 0);
	pdata->st->st_blocks = strtol(argv[i++], NULL, 0);
	pdata->st->st_atim.tv_sec = strtol(argv[i++], NULL, 0);
	pdata->st->st_atim.tv_nsec = strtol(argv[i++], NULL, 0);
	pdata->st->st_mtim.tv_sec = strtol(argv[i++], NULL, 0);
	pdata->st->st_mtim.tv_nsec = strtol(argv[i++], NULL, 0);
	pdata->st->st_ctim.tv_sec = strtol(argv[i++], NULL, 0);
	pdata->st->st_ctim.tv_nsec = strtol(argv[i++], NULL, 0);

	return SQLITE_OK;
}

struct readlink_data {
	int error;
	char *buf;
	size_t len;
};

static int readlink_cb(void *data, int argc, char **argv, char **colname)
{
	struct readlink_data *pdata = (struct readlink_data *)data;
	int i;
	(void)argc;
	(void)colname;

	i = 1;
	pdata->error = strlen(argv[i]) >= pdata->len ? ENAMETOOLONG : 0;
	strncpy(pdata->buf, argv[i++], pdata->len);

	return SQLITE_OK;
}

struct readdir_data {
	const char *parent;
	void *buffer;
	fuse_fill_dir_t filler;
	int count;
};

static int readdir_cb(void *data, int argc, char **argv, char **colname)
{
	struct readdir_data *pdata = (struct readdir_data *)data;
	(void)argc;	
	(void)colname;

	if (strcmp(pdata->parent, argv[0]) != 0) {
		if (pdata->buffer && pdata->filler)
			pdata->filler(pdata->buffer, basename(argv[0]), NULL,
				      0, 0);
		pdata->count++;
	}

	return SQLITE_OK;
}

static int __readdir(sqlite3 *db, const char *path, void *buffer,
		     fuse_fill_dir_t filler, off_t offset,
		     struct fuse_file_info *fi,
		     enum fuse_readdir_flags flags)
{
	struct readdir_data data = {
		.parent = path,
		.buffer = buffer,
		.filler = filler,
		.count = 0,
	};
	char sql[BUFSIZ];
	char *e;
	int ret;
	(void)offset;
	(void)flags;
	(void)fi;

	if (!db || !path)
		return -EINVAL;

	if (buffer && filler) {
		filler(buffer, ".", NULL, 0, 0);
		filler(buffer, "..", NULL, 0, 0);
	}
	data.count += 2;

	snprintf(sql, sizeof(sql), "SELECT path "
				   "FROM files "
				   "WHERE parent = \"%s\";",
		 path);
	ret = sqlite3_exec(db, sql, readdir_cb, &data, &e);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return data.count;
}

struct orphan_data {
	int count;
};

static int orphan_cb(void *data, int argc, char **argv, char **colname)
{
	struct orphan_data *pdata = (struct orphan_data *)data;
	(void)argc;	
	(void)colname;

	fprintf(stderr, "%s\n", argv[0]);
	pdata->count++;

	return SQLITE_OK;
}

static int lost_found(sqlite3 *db)
{
	struct orphan_data data = {
		.count = 0,
	};
	char sql[BUFSIZ];
	char *e;
	int ret;

	if (!db)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "SELECT path "
				   "FROM files "
				   "WHERE parent NOT IN ("
				  	"SELECT path FROM files"
				   ");");
	ret = sqlite3_exec(db, sql, orphan_cb, &data, &e);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return data.count;
}

static int add_file(sqlite3 *db, const char *path, const void *data,
		    size_t datasize, const struct stat *st)
{
	char sql[BUFSIZ], parent[PATH_MAX];
	int ret = -EIO;

	if (!db || !path || !st)
		return -EINVAL;

	strncpy(parent, path, sizeof(parent));
	dirname(parent);

	snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO files(path, parent, "
		 "data, st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, "
		 "st_rdev, st_size, st_blksize, st_blocks, st_atim_sec, "
		 "st_atim_nsec, st_mtim_sec, st_mtim_nsec, st_ctim_sec, "
		 "st_ctim_nsec) "
		 "VALUES(\"%s\", \"%s\", ?, %lu, %lu, %u, %lu, %u, %u, %lu, "
		 "%lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu);",
		 path, parent, st->st_dev, st->st_ino, st->st_mode,
		 st->st_nlink, st->st_uid, st->st_gid, st->st_rdev, data ? datasize : 0,
		 st->st_blksize, st->st_blocks, st->st_atim.tv_sec,
		 st->st_atim.tv_nsec, st->st_mtim.tv_sec, st->st_mtim.tv_nsec,
		 st->st_ctim.tv_sec, st->st_ctim.tv_nsec);

	for (;;) {
		sqlite3_stmt *stmt;

		if (sqlite3_prepare(db, sql, -1, &stmt, 0) != SQLITE_OK) {
			__sqlite3_perror("sqlite3_prepare", db);
			goto exit;
		}

		if (sqlite3_bind_blob(stmt, 1, data, datasize, SQLITE_STATIC)) {
			__sqlite3_perror("sqlite3_bind_blob", db);
			goto exit;
		}

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			__sqlite3_perror("sqlite3_step", db);
			goto exit;
		}

		if (sqlite3_finalize(stmt) == SQLITE_SCHEMA) {
			__sqlite3_perror("sqlite3_step", db);
			continue;
		}

		ret = 0;
		break;
	}

exit:
	return ret;
}

static int add_symlink(sqlite3 *db, const char *linkname, const char *path)
{
	char sql[BUFSIZ], parent[PATH_MAX];
	struct timespec now;
	struct stat st;
	char *e;
	int ret;

	if (!db || !linkname || !path)
		return -EINVAL;

	if (clock_gettime(CLOCK_REALTIME, &now)) {
		perror("clock_gettime");
		return -errno;
	}

	strncpy(parent, path, sizeof(parent));
	dirname(parent);

	snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO symlinks(path, parent, "
		 "linkname) "
		 "VALUES(\"%s\", \"%s\", \"%s\");",
		 path, parent, linkname);
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	memset(&st, 0, sizeof(struct stat));
	/* Ignored st.st_dev = 0; */
	/* Ignored st.st_ino = 0; */
	st.st_mode = S_IFLNK;
	st.st_nlink = 2;
	st.st_uid = getuid();
	st.st_gid = getgid();
	/* Ignored st.st_blksize = 0; */
	st.st_atim = now;
	st.st_mtim = now;
	st.st_ctim = now;

	ret = add_file(db, path, NULL, 0, &st);
	if (ret) {
		snprintf(sql, sizeof(sql), "DELETE FROM symlinks "
					   "WHERE path=\"%s\";",
			 path);
		if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
			fprintf(stderr, "sqlite3_exec: %s\n", e);
			sqlite3_free(e);
		}

		return ret;
	}

	return ret;
}

static int add_directory(sqlite3 *db, const char *path, const struct stat *st)
{
	char sql[BUFSIZ], parent[PATH_MAX];
	char *e;

	if (!db || !path || !st)
		return -EINVAL;

	strncpy(parent, path, sizeof(parent));
	dirname(parent);

	snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO files(path, parent, "
		 "st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, st_rdev, "
		 "st_size, st_blksize, st_blocks, st_atim_sec, st_atim_nsec, "
		 "st_mtim_sec, st_mtim_nsec, st_ctim_sec, st_ctim_nsec) "
		 "VALUES(\"%s\", \"%s\", %lu, %lu, %u, %lu, %u, %u, %lu, %lu, "
		 "%lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu);",
		 path, parent, st->st_dev, st->st_ino, st->st_mode,
		 st->st_nlink, st->st_uid, st->st_gid, st->st_rdev, st->st_size,
		 st->st_blksize, st->st_blocks, st->st_atim.tv_sec,
		 st->st_atim.tv_nsec, st->st_mtim.tv_sec, st->st_mtim.tv_nsec,
		 st->st_ctim.tv_sec, st->st_ctim.tv_nsec);
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return 0;
}

static int __stat(sqlite3 *db, const char *path, struct stat *st)
{
	struct getattr_data data = {
		.error = ENOENT,
		.st = st,
	};
	char sql[BUFSIZ];
	char *e;
	int ret;

	if (!db || !st)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "SELECT "
					"path, "
					"st_dev, "
					"st_ino, "
					"st_mode, "
					"st_nlink, "
					"st_uid, "
					"st_gid, "
					"st_rdev, "
					"st_size, "
					"st_blksize, "
					"st_blocks, "
					"st_atim_sec, "
					"st_atim_nsec, "
					"st_mtim_sec, "
					"st_mtim_nsec, "
					"st_ctim_sec, "
					"st_ctim_nsec "
				   "FROM files WHERE path = \"%s\";",
		 path);
	ret = sqlite3_exec(db, sql, getattr_cb, &data, &e);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	if (data.error)
		return -data.error;

	if (DEBUG >= 2)
		fprintstat(stderr, path, st);

	return 0;
}

static int __chmod(sqlite3 *db, const char *path, mode_t mode)
{
	char sql[BUFSIZ];
	char *e;

	if (!db)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "UPDATE files SET "
					"st_mode=%u "
				   "WHERE path=\"%s\";",
		 mode, path);
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return 0;
}

static int __chown(sqlite3 *db, const char *path, uid_t uid, gid_t gid)
{
	char sql[BUFSIZ];
	char *e;

	if (!db)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "UPDATE files SET "
					"st_uid=%u, "
					"st_gid=%u "
				   "WHERE path=\"%s\";",
		 uid, gid, path);
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return 0;
}

static int __utimens(sqlite3 *db, const char *path, const struct timespec tv[2])
{
	struct timespec atime, mtime;
	char sql[BUFSIZ];
	char *e;

	if (!db || !path)
		return -EINVAL;

	if (!tv || tv[0].tv_nsec == UTIME_NOW) {
		 if (clock_gettime(CLOCK_REALTIME, &atime)) {
			 perror("clock_gettime");
			 return -errno;
		 }
	} else {
		atime.tv_sec = tv[0].tv_sec;
		atime.tv_nsec = tv[0].tv_nsec;
	}

	if (!tv || tv[1].tv_nsec == UTIME_NOW) {
		 if (clock_gettime(CLOCK_REALTIME, &mtime)) {
			 perror("clock_gettime");
			 return -errno;
		 }
	} else {
		mtime.tv_sec = tv[1].tv_sec;
		mtime.tv_nsec = tv[1].tv_nsec;
	}

	if (tv[0].tv_nsec != UTIME_OMIT && tv[1].tv_nsec != UTIME_OMIT)
		snprintf(sql, sizeof(sql), "UPDATE files SET "
						"st_atim_sec=%lu, "
						"st_atim_nsec=%lu, "
						"st_mtim_sec=%lu, "
						"st_mtim_nsec=%lu "
					   "WHERE path=\"%s\";",
			 atime.tv_sec, atime.tv_nsec,
			 mtime.tv_sec, mtime.tv_nsec,
			 path);
	else if (tv[0].tv_nsec != UTIME_OMIT)
		snprintf(sql, sizeof(sql), "UPDATE files SET "
						"st_atim_sec=%lu, "
						"st_atim_nsec=%lu, "
					   "WHERE path=\"%s\";",
			 atime.tv_sec, atime.tv_nsec, path);
	else if (tv[1].tv_nsec != UTIME_OMIT)
		snprintf(sql, sizeof(sql), "UPDATE files SET "
						"st_mtim_sec=%lu, "
						"st_mtim_nsec=%lu "
					   "WHERE path=\"%s\";",
			 mtime.tv_sec, mtime.tv_nsec, path);
	else
		return 0;
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return 0;
}

static ssize_t __pread(sqlite3 *db, const char *path, char *buf,
		       size_t bufsize, off_t offset)
{
	int ret = -ENOENT;
	ssize_t size = 0;
	char sql[BUFSIZ];

	if (!db || !buf)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "SELECT data "
				   "FROM files "
				   "WHERE (path == \"%s\");",
		 path);

	for (;;) {
		const unsigned char *data;
		sqlite3_stmt *stmt;
		int datasize;

		if (sqlite3_prepare(db, sql, -1, &stmt, 0)) {
			__sqlite3_perror("sqlite3_prepare", db);
			ret = -EIO;
			goto exit;
		}

		if (sqlite3_step(stmt) != SQLITE_ROW) {
			__sqlite3_perror("sqlite3_step", db);
			ret = -EIO;
			goto exit;
		}

		data = sqlite3_column_blob(stmt, 0);
		datasize = sqlite3_column_bytes(stmt, 0);
		size = datasize - offset;

		if (size < 0) {
			size = 0;
			buf[0] = 0;
		} else {
			size = __min((size_t)size, bufsize);
			memcpy(buf, &data[offset], size);
		}

		if (sqlite3_finalize(stmt) == SQLITE_SCHEMA) {
			__sqlite3_perror("sqlite3_step", db);
			ret = -EIO;
			continue;
		}

		ret = 0;
		break;
	}

exit:
	if (ret)
		return ret;

	hexdebug2(offset, buf, size);

	return size;
}

static ssize_t __pwrite(sqlite3 *db, const char *path, const char *buf,
			size_t bufsize, off_t offset)
{
	ssize_t datasize = 0;
	void *data = NULL;
	struct stat st;
	int ret;

	if (!db || !buf)
		return -EINVAL;

	ret = __stat(db, path, &st);
	if (ret)
		return ret;

	if (offset) {
		ssize_t s;

		datasize = __max(st.st_size, offset);
		datasize += bufsize;
		data = malloc(datasize);
		if (!data) {
			ret = -ENOMEM;
			goto exit;
		}

		s = __pread(db, path, data, st.st_size, 0);
		if (s < 0) {
			ret = s;
			goto exit;
		} else if (s < st.st_size) {
			ret = -ENOMEM;
			goto exit;
		}

		if (st.st_size < offset)
			memset(data + st.st_size, 0, offset - st.st_size);

		memcpy(data + offset, buf, bufsize);

		ret = add_file(db, path, data, datasize, &st);
		if (ret)
			goto exit;

		goto exit;
	}

	ret = add_file(db, path, buf, bufsize, &st);
	if (ret)
		return ret;

exit:
	if (data)
		free(data);

	if (ret)
		return ret;

	hexdebug2(offset, buf, bufsize);

	return bufsize;
}

static int __truncate(sqlite3 *db, const char *path, off_t size)
{
	void *data = NULL;
	char sql[BUFSIZ];
	struct stat st;
	int ret;
	char *e;

	if (!db || !path)
		return -EINVAL;

	ret = __stat(db, path, &st);
	if (ret)
		return ret;

	data = malloc(size);
	ret = __pread(db, path, data, size, 0);
	if (ret)
		goto exit;

	ret = -EIO;
	snprintf(sql, sizeof(sql), "UPDATE files SET "
					"st_size=%lu, "
					"data=? "
				   "WHERE path=\"%s\";",
		 st.st_size, path);
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		goto exit;
	}

	for (;;) {
		sqlite3_stmt *stmt;

		if (sqlite3_prepare(db, sql, -1, &stmt, 0) != SQLITE_OK) {
			__sqlite3_perror("sqlite3_prepare", db);
			goto exit;
		}

		if (sqlite3_bind_blob(stmt, 1, data, size, SQLITE_STATIC)) {
			__sqlite3_perror("sqlite3_bind_blob", db);
			goto exit;
		}

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			__sqlite3_perror("sqlite3_step", db);
			goto exit;
		}

		if (sqlite3_finalize(stmt) == SQLITE_SCHEMA) {
			__sqlite3_perror("sqlite3_step", db);
			continue;
		}

		ret = 0;
		break;
	}

exit:
	if (data)
		free(data);

	return ret;
}

static int __mknod(sqlite3 *db, const char *path, mode_t mode, dev_t rdev)
{
	struct timespec now;
	struct stat st;

	if (!db || !path)
		return -EINVAL;

	if (clock_gettime(CLOCK_REALTIME, &now)) {
		perror("clock_gettime");
		return -errno;
	}

	memset(&st, 0, sizeof(struct stat));
	st.st_dev = rdev;
	/* Ignored st.st_ino = 0; */
	st.st_mode = mode;
	st.st_nlink = 1;
	st.st_uid = getuid();
	st.st_gid = getgid();
	/* Ignored st.st_blksize = 0; */
	st.st_atim = now;
	st.st_mtim = now;
	st.st_ctim = now;

	if (add_file(db, path, NULL, 0, &st))
		return -EIO;

	return 0;
}

static int __rename(sqlite3 *db, const char *oldpath, const char *newpath)
{
	char sql[BUFSIZ];
	char *e;

	if (!db || !oldpath || !newpath)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "UPDATE files SET "
					"path=\"%s\" "
				   "WHERE path=\"%s\";",
		 newpath, oldpath);
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return 0;
}

static int __unlink(sqlite3 *db, const char *path)
{
	char sql[BUFSIZ];
	char *e;

	if (!db || !path)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "DELETE FROM files "
				   "WHERE path=\"%s\";",
		 path);
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	snprintf(sql, sizeof(sql), "DELETE FROM symlinks "
				   "WHERE path=\"%s\";",
		 path);
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return 0;
}

static int __symlink(sqlite3 *db, const char *linkname, const char *path)
{
	return add_symlink(db, linkname, path);
}

static int __readlink(sqlite3 *db, const char *path, char *buf, size_t len)
{
	struct readlink_data data = {
		.error = ENOENT,
		.buf = buf,
		.len = len,
	};
	char sql[BUFSIZ];
	char *e;
	int ret;

	if (!db || !path || !buf)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "SELECT "
					"path, "
					"linkname "
				   "FROM symlinks WHERE path = \"%s\";",
		 path);
	ret = sqlite3_exec(db, sql, readlink_cb, &data, &e);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	if (data.error)
		return -data.error;

	if (DEBUG)
		fprintf(stderr, "%s\n", buf);

	return 0;
}

static int __mkdir(sqlite3 *db, const char *path, mode_t mode)
{
	struct timespec now;
	struct stat st;

	if (!db || !path)
		return -EINVAL;

	if (clock_gettime(CLOCK_REALTIME, &now)) {
		perror("clock_gettime");
		return -errno;
	}

	memset(&st, 0, sizeof(struct stat));
	/* Ignored st.st_dev = 0; */
	/* Ignored st.st_ino = 0; */
	st.st_mode = S_IFDIR | mode;
	st.st_nlink = 2;
	st.st_uid = getuid();
	st.st_gid = getgid();
	/* Ignored st.st_blksize = 0; */
	st.st_atim = now;
	st.st_mtim = now;
	st.st_ctim = now;

	return add_directory(db, path, &st);
}

static int __rmdir(sqlite3 *db, const char *path)
{
	int ret = __readdir(db, path, NULL, NULL, 0, NULL, 0);
	if (ret < 0)
		return ret;
	else if (ret > 2)
		return -ENOTEMPTY;

	return __unlink(db, path);
}

static int __mkdir_lost_found(sqlite3 *db)
{
	struct stat st;
	const char *path = "/.lost+found";
	int ret;

	if (!db)
		return -EINVAL;

	ret = __stat(db, path, &st);
	if (ret == 0)
		return 0;
	else if (ret != -ENOENT)
		return ret;

	ret = __mkdir(db, path, 0755);
	if (ret)
		return ret;

	return 0;
}

static int mkfs(const char *path)
{
	char sql[BUFSIZ];
	struct stat st;
	sqlite3 *db;
	int exists;
	char *e;

	if (!path)
		return -EINVAL;

	exists = stat(path, &st) == 0;
	if (exists)
		return -EEXIST;

	if (sqlite3_open(path, &db)) {
		__sqlite3_perror("sqlite3_open", db);
		goto error;
	}

	snprintf(sql, sizeof(sql),
		 "CREATE TABLE IF NOT EXISTS files("
				"path TEXT NOT NULL PRIMARY KEY, "
				"parent TEXT NOT NULL, "
				"data BLOB, "
				"st_dev INT(8), "
				"st_ino INT(8), "
				"st_mode INT(4), "
				"st_nlink INT(8), "
				"st_uid INT(4), "
				"st_gid INT(4), "
				"st_rdev INT(8), "
				"st_size INT(8), "
				"st_blksize INT(8), "
				"st_blocks INT(8), "
				"st_atim_sec INT(8), "
				"st_atim_nsec INT(8), "
				"st_mtim_sec INT(8), "
				"st_mtim_nsec INT(8), "
				"st_ctim_sec INT(8), "
				"st_ctim_nsec INT(8));");
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		goto error;
	}

	snprintf(sql, sizeof(sql),
		 "CREATE TABLE IF NOT EXISTS symlinks("
				"path TEXT NOT NULL PRIMARY KEY, "
				"parent TEXT NOT NULL, "
				"linkname TEXT NOT NULL);");
	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		goto error;
	}

	if (__mkdir(db, "/", 0755))
		goto error;

	if (__mkdir_lost_found(db))
		goto error;

	return 0;

error:
	sqlite3_close(db);
	return -EIO;
}

static int fsck(const char *path)
{
	int ret;

	if (!path)
		return -EINVAL;

	ret = system("sqlitefs-fsck");
	if (ret == -1)
		__exit_perror("system", -ret);

	if (WIFSIGNALED(ret))
		fprintf(stderr, "%s\n", strsignal(WTERMSIG(ret)));
	else if (WIFEXITED(ret))
		return WEXITSTATUS(ret);

	return ret;
}

/**
 * The file system operations:
 *
 * Most of these should work very similarly to the well known UNIX
 * file system operations.  A major exception is that instead of
 * returning an error in 'errno', the operation should return the
 * negated error value (-errno) directly.
 *
 * All methods are optional, but some are essential for a useful
 * filesystem (e.g. getattr).  Open, flush, release, fsync, opendir,
 * releasedir, fsyncdir, access, create, truncate, lock, init and
 * destroy are special purpose methods, without which a full featured
 * filesystem can still be implemented.
 *
 * In general, all methods are expected to perform any necessary
 * permission checking. However, a filesystem may delegate this task
 * to the kernel by passing the `default_permissions` mount option to
 * `fuse_new()`. In this case, methods will only be called if
 * the kernel's permission check has succeeded.
 *
 * Almost all operations take a path which can be of any length.
 */

/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored. The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given. In that case it is passed to userspace,
 * but libfuse and the kernel will still assign a different
 * inode for internal use (called the "nodeid").
 *
 * `fi` will always be NULL if the file is not currently open, but
 * may also be NULL if the file is open.
 */
static int sqlitefs_getattr(const char *path, struct stat *st,
			    struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)fi;

	return __stat(db, path, st);
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.	If the linkname is too long to fit in the
 * buffer, it should be truncated.	The return value should be 0
 * for success.
 */
static int sqlitefs_readlink(const char *path, char *buf, size_t len)
{
	sqlite3 *db = fuse_get_context()->private_data;

	return __readlink(db, path, buf, len);
}

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
static int sqlitefs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	sqlite3 *db = fuse_get_context()->private_data;

	return __mknod(db, path, mode, rdev);
}

/** Create a directory
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 */
static int sqlitefs_mkdir(const char *path, mode_t mode)
{
	sqlite3 *db = fuse_get_context()->private_data;

	return __mkdir(db, path, mode);
}

/** Remove a file */
static int sqlitefs_unlink(const char *path)
{
	sqlite3 *db = fuse_get_context()->private_data;

	return __unlink(db, path);
}

/** Remove a directory */
static int sqlitefs_rmdir(const char *path)
{
	sqlite3 *db = fuse_get_context()->private_data;

	return __rmdir(db, path);
}

/** Create a symbolic link */
static int sqlitefs_symlink(const char *linkname, const char *path)
{
	sqlite3 *db = fuse_get_context()->private_data;

	return __symlink(db, linkname, path);
}

/** Rename a file
 *
 * *flags* may be `RENAME_EXCHANGE` or `RENAME_NOREPLACE`. If
 * RENAME_NOREPLACE is specified, the filesystem must not
 * overwrite *newname* if it exists and return an error
 * instead. If `RENAME_EXCHANGE` is specified, the filesystem
 * must atomically exchange the two files, i.e. both must
 * exist and neither may be deleted.
 */
static int sqlitefs_rename(const char *oldpath, const char *newpath,
			   unsigned int flags)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)flags;

	return __rename(db, oldpath, newpath);
}

/** Create a hard link to a file */
/* int (*link) (const char *, const char *); */

/** Change the permission bits of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 */
static int sqlitefs_chmod(const char *path, mode_t mode,
			  struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)fi;

	return __chmod(db, path, mode);
}

/** Change the owner and group of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
static int sqlitefs_chown(const char *path, uid_t uid, gid_t gid,
			  struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)fi;

	return __chown(db, path, uid, gid);
}

/** Change the size of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
static int sqlitefs_truncate(const char *path, off_t size,
			     struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)fi;

	return __truncate(db, path, size);
}

/** Open a file
 *
 * Open flags are available in fi->flags. The following rules
 * apply.
 *
 *  - Creation (O_CREAT, O_EXCL, O_NOCTTY) flags will be
 *    filtered out / handled by the kernel.
 *
 *  - Access modes (O_RDONLY, O_WRONLY, O_RDWR, O_EXEC, O_SEARCH)
 *    should be used by the filesystem to check if the operation is
 *    permitted.  If the ``-o default_permissions`` mount option is
 *    given, this check is already done by the kernel before calling
 *    open() and may thus be omitted by the filesystem.
 *
 *  - When writeback caching is enabled, the kernel may send
 *    read requests even for files opened with O_WRONLY. The
 *    filesystem should be prepared to handle this.
 *
 *  - When writeback caching is disabled, the filesystem is
 *    expected to properly handle the O_APPEND flag and ensure
 *    that each write is appending to the end of the file.
 * 
 *  - When writeback caching is enabled, the kernel will
 *    handle O_APPEND. However, unless all changes to the file
 *    come through the kernel this will not work reliably. The
 *    filesystem should thus either ignore the O_APPEND flag
 *    (and let the kernel handle it), or return an error
 *    (indicating that reliably O_APPEND is not available).
 *
 * Filesystem may store an arbitrary file handle (pointer,
 * index, etc) in fi->fh, and use this in other all other file
 * operations (read, write, flush, release, fsync).
 *
 * Filesystem may also implement stateless file I/O and not store
 * anything in fi->fh.
 *
 * There are also some flags (direct_io, keep_cache) which the
 * filesystem may set in fi, to change the way the file is opened.
 * See fuse_file_info structure in <fuse_common.h> for more details.
 *
 * If this request is answered with an error code of ENOSYS
 * and FUSE_CAP_NO_OPEN_SUPPORT is set in
 * `fuse_conn_info.capable`, this is treated as success and
 * future calls to open will also succeed without being send
 * to the filesystem process.
 *
 */
/* int (*open) (const char *, struct fuse_file_info *); */

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.	 An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 */
static int sqlitefs_read(const char *path, char *buf, size_t bufsize,
			 off_t offset, struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)fi;

	return __pread(db, path, buf, bufsize, offset);
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.	 An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
static int sqlitefs_write(const char *path, const char *buf, size_t bufsize,
			  off_t offset, struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)fi;

	return __pwrite(db, path, buf, bufsize, offset);
}

/** Get file system statistics
 *
 * The 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 */
/* int (*statfs) (const char *, struct statvfs *); */

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor, as opposed to
 * release which is called on the close of the last file descriptor for
 * a file.  Under Linux, errors returned by flush() will be passed to 
 * userspace as errors from close(), so flush() is a good place to write
 * back any cached dirty data. However, many applications ignore errors 
 * on close(), and on non-Linux systems, close() may succeed even if flush()
 * returns an error. For these reasons, filesystems should not assume
 * that errors returned by flush will ever be noticed or even
 * delivered.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers to an
 * open file handle, e.g. due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush should
 * be treated equally.  Multiple write-flush sequences are relatively
 * rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will be called at any
 * particular point.  It may be called more times than expected, or not
 * at all.
 *
 * [close]: http://pubs.opengroup.org/onlinepubs/9699919799/functions/close.html
 */
/* int (*flush) (const char *, struct fuse_file_info *); */

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file handle.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 */
/* int (*release) (const char *, struct fuse_file_info *); */

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 */
/* int (*fsync) (const char *, int, struct fuse_file_info *); */

/** Set extended attributes */
/* int (*setxattr) (const char *, const char *, const char *, size_t, int); */

/** Get extended attributes */
/* int (*getxattr) (const char *, const char *, char *, size_t); */

/** List extended attributes */
/* int (*listxattr) (const char *, char *, size_t); */

/** Remove extended attributes */
/* int (*removexattr) (const char *, const char *); */

/** Open directory
 *
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this
 * directory. Optionally opendir may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to readdir, releasedir and fsyncdir.
 */
/* int (*opendir) (const char *, struct fuse_file_info *); */

/** Read directory
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 */
static int sqlitefs_readdir(const char *path, void *buffer,
			    fuse_fill_dir_t filler, off_t offset,
			    struct fuse_file_info *fi,
			    enum fuse_readdir_flags flags)
{
	sqlite3 *db = fuse_get_context()->private_data;
	int ret;

	ret = __readdir(db, path, buffer, filler, offset, fi, flags);
	if (ret < 0)
		return ret;

	return 0;
}

/** Release directory
 */
/* int (*releasedir) (const char *, struct fuse_file_info *); */

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 */
/* int (*fsyncdir) (const char *, int, struct fuse_file_info *); */

/**
 * Initialize filesystem
 *
 * The return value will passed in the `private_data` field of
 * `struct fuse_context` to all file operations, and as a
 * parameter to the destroy() method. It overrides the initial
 * value provided to fuse_main() / fuse_new().
 */
/* void *(*init) (struct fuse_conn_info *conn,
		  struct fuse_config *cfg); */

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 */
/* void (*destroy) (void *private_data); */

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 */
/* int (*access) (const char *, int); */

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 */
/* int (*create) (const char *, mode_t, struct fuse_file_info *); */

/**
 * Perform POSIX file locking operation
 *
 * The cmd argument will be either F_GETLK, F_SETLK or F_SETLKW.
 *
 * For the meaning of fields in 'struct flock' see the man page
 * for fcntl(2).  The l_whence field will always be set to
 * SEEK_SET.
 *
 * For checking lock ownership, the 'fuse_file_info->owner'
 * argument must be used.
 *
 * For F_GETLK operation, the library will first check currently
 * held locks, and if a conflicting lock is found it will return
 * information without calling this method.	 This ensures, that
 * for local locks the l_pid field is correctly filled in.	The
 * results may not be accurate in case of race conditions and in
 * the presence of hard links, but it's unlikely that an
 * application would rely on accurate GETLK results in these
 * cases.  If a conflicting lock is not found, this method will be
 * called, and the filesystem may fill out l_pid by a meaningful
 * value, or it may leave this field zero.
 *
 * For F_SETLK and F_SETLKW the l_pid field will be set to the pid
 * of the process performing the locking operation.
 *
 * Note: if this method is not implemented, the kernel will still
 * allow file locking to work locally.  Hence it is only
 * interesting for network filesystems and similar.
 */
/* int (*lock) (const char *, struct fuse_file_info *, int cmd,
		struct flock *); */

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * This supersedes the old utime() interface.  New applications
 * should use this.
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 *
 * See the utimensat(2) man page for details.
 */
static int sqlitefs_utimens(const char *path, const struct timespec tv[2],
			    struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)fi;

	return __utimens(db, path, tv);
}

/**
 * Map block index within file to block index within device
 *
 * Note: This makes sense only for block device backed filesystems
 * mounted with the 'blkdev' option
 */
/* int (*bmap) (const char *, size_t, uint64_t *); */

/**
 * Ioctl
 *
 * flags will have FUSE_IOCTL_COMPAT set for 32bit ioctls in
 * 64bit environment.  The size and direction of data is
 * determined by _IOC_*() decoding of cmd.  For _IOC_NONE,
 * data will be NULL, for _IOC_WRITE data is out area, for
 * _IOC_READ in area and if both are set in/out area.  In all
 * non-NULL cases, the area is of _IOC_SIZE(cmd) bytes.
 *
 * If flags has FUSE_IOCTL_DIR then the fuse_file_info refers to a
 * directory file handle.
 *
 * Note : the unsigned long request submitted by the application
 * is truncated to 32 bits.
 */
/* int (*ioctl) (const char *, unsigned int cmd, void *arg,
		 struct fuse_file_info *, unsigned int, void *); */

/**
 * Poll for IO readiness events
 *
 * Note: If ph is non-NULL, the client should notify
 * when IO readiness events occur by calling
 * fuse_notify_poll() with the specified ph.
 *
 * Regardless of the number of times poll with a non-NULL ph
 * is received, single notification is enough to clear all.
 * Notifying more times incurs overhead but doesn't harm
 * correctness.
 *
 * The callee is responsible for destroying ph with
 * fuse_pollhandle_destroy() when no longer in use.
 */
/* int (*poll) (const char *, struct fuse_file_info *,
		struct fuse_pollhandle *, unsigned *); */

/** Write contents of buffer to an open file
 *
 * Similar to the write() method, but data is supplied in a
 * generic buffer.  Use fuse_buf_copy() to transfer data to
 * the destination.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
/* int (*write_buf) (const char *, struct fuse_bufvec *buf, off_t off,
		     struct fuse_file_info *); */

/** Store data from an open file in a buffer
 *
 * Similar to the read() method, but data is stored and
 * returned in a generic buffer.
 *
 * No actual copying of data has to take place, the source
 * file descriptor may simply be stored in the buffer for
 * later data transfer.
 *
 * The buffer must be allocated dynamically and stored at the
 * location pointed to by bufp.  If the buffer contains memory
 * regions, they too must be allocated using malloc().  The
 * allocated memory will be freed by the caller.
 */
/* int (*read_buf) (const char *, struct fuse_bufvec **bufp,
		    size_t size, off_t off, struct fuse_file_info *); */

/**
 * Perform BSD file locking operation
 *
 * The op argument will be either LOCK_SH, LOCK_EX or LOCK_UN
 *
 * Nonblocking requests will be indicated by ORing LOCK_NB to
 * the above operations
 *
 * For more information see the flock(2) manual page.
 *
 * Additionally fi->owner will be set to a value unique to
 * this open file.  This same value will be supplied to
 * ->release() when the file is released.
 *
 * Note: if this method is not implemented, the kernel will still
 * allow file locking to work locally.  Hence it is only
 * interesting for network filesystems and similar.
 */
/* int (*flock) (const char *, struct fuse_file_info *, int op); */

/**
 * Allocates space for an open file
 *
 * This function ensures that required space is allocated for specified
 * file.  If this function returns success then any subsequent write
 * request to specified range is guaranteed not to fail because of lack
 * of space on the file system media.
 */
/* int (*fallocate) (const char *, int, off_t, off_t,
		     struct fuse_file_info *); */

/**
 * Copy a range of data from one file to another
 *
 * Performs an optimized copy between two file descriptors without the
 * additional cost of transferring data through the FUSE kernel module
 * to user space (glibc) and then back into the FUSE filesystem again.
 *
 * In case this method is not implemented, glibc falls back to reading
 * data from the source and writing to the destination. Effectively
 * doing an inefficient copy of the data.
 */
/* ssize_t (*copy_file_range) (const char *path_in,
			       struct fuse_file_info *fi_in,
			       off_t offset_in, const char *path_out,
			       struct fuse_file_info *fi_out,
			       off_t offset_out, size_t size, int flags); */

static struct fuse_operations operations = {
	.getattr = sqlitefs_getattr,
	.readlink = sqlitefs_readlink,
	.mknod = sqlitefs_mknod,
	.mkdir = sqlitefs_mkdir,
	.unlink = sqlitefs_unlink,
	.rmdir = sqlitefs_rmdir,
	.symlink = sqlitefs_symlink,
	.rename = sqlitefs_rename,
	/* .link */
	.chmod = sqlitefs_chmod,
	.chown = sqlitefs_chown,
	.truncate = sqlitefs_truncate,
	/* .open */
	.read = sqlitefs_read,
	.write = sqlitefs_write,
	/* .flush */
	/* .release */
	/* .fsync */
	/* .setxattr */
	/* .getxattr */
	/* .removexattr */
	/* .opendir */
	.readdir = sqlitefs_readdir,
	/* .releasedir */
	/* .fsyncdir */
	/* .init */
	/* .destroy */
	/*.access */
	/*.create */
	/*.lock */
	.utimens = sqlitefs_utimens,
	/*.bmap */
	/*.ioctl */
	/* .poll */
	/* .write_buf */
	/* .read_buf */
	/* .flock */
	/* .fallocate */
	/* .copy_file_range */
};

struct sqlitefs_cmdline_opts {
	struct fuse_cmdline_opts base;
	char *file;
	const char *command;
};

#define FUSE_HELPER_OPT(t, p) \
	{ t, offsetof(struct fuse_cmdline_opts, p), 1 }

static const struct fuse_opt sqlitefs_opts[] = {
	FUSE_HELPER_OPT("-h",		show_help),
	FUSE_HELPER_OPT("--help",	show_help),
	FUSE_HELPER_OPT("-V",		show_version),
	FUSE_HELPER_OPT("--version",	show_version),
	FUSE_HELPER_OPT("-d",		debug),
	FUSE_HELPER_OPT("debug",	debug),
	FUSE_HELPER_OPT("-d",		foreground),
	FUSE_HELPER_OPT("debug",	foreground),
	FUSE_OPT_KEY("-d",		FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("debug",		FUSE_OPT_KEY_KEEP),
	FUSE_HELPER_OPT("-f",		foreground),
	FUSE_HELPER_OPT("-s",		singlethread),
	FUSE_HELPER_OPT("fsname=",	nodefault_subtype),
	FUSE_OPT_KEY("fsname=",		FUSE_OPT_KEY_KEEP),
#ifndef __FreeBSD__
	FUSE_HELPER_OPT("subtype=",	nodefault_subtype),
	FUSE_OPT_KEY("subtype=",	FUSE_OPT_KEY_KEEP),
#endif
	FUSE_HELPER_OPT("clone_fd",	clone_fd),
	FUSE_HELPER_OPT("max_idle_threads=%u", max_idle_threads),
	FUSE_OPT_END
};

int fuse_mnt_parse_fuse_fd(const char *mountpoint)
{
	int fd = -1;
	size_t len = 0;

	if (sscanf(mountpoint, "/dev/fd/%u%ln", &fd, &len) == 1 &&
	    len == strlen(mountpoint)) {
		return fd;
	}

	return -1;
}

static int sqlitefs_opt_proc(void *data, const char *arg, int key,
			     struct fuse_args *outargs)
{
	(void) outargs;
	struct sqlitefs_cmdline_opts *sqlitefs_opts = data;
	struct fuse_cmdline_opts *opts = data;

	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
		if (!sqlitefs_opts->file) {
			return fuse_opt_add_opt(&sqlitefs_opts->file, arg);
		} else if (!opts->mountpoint) {
			if (fuse_mnt_parse_fuse_fd(arg) != -1) {
				return fuse_opt_add_opt(&opts->mountpoint, arg);
			}

			char mountpoint[PATH_MAX] = "";
			if (realpath(arg, mountpoint) == NULL) {
				fuse_log(FUSE_LOG_ERR,
					"fuse: bad mount point `%s': %s\n",
					arg, strerror(errno));
				return -1;
			}
			return fuse_opt_add_opt(&opts->mountpoint, mountpoint);
		} else if (!sqlitefs_opts->command) {
			sqlitefs_opts->command = arg;
			opts->foreground = 1;
		}
		return 0;

	default:
		/* Pass through unknown options */
		return 1;
	}
}

struct thread_opts {
	pthread_t main_thread;
	char **argv;
	int argc;
	int status;
};

static int fork_execv(int argc, char **argv)
{
	int status;
	pid_t pid;
	(void)argc;

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return -errno;
	}

	if (pid) {
		if (waitpid(pid, &status, 0) == -1) {
			perror("waitpid");
			return -errno;
		}

		return status;
	}

	execv(argv[0], argv);
	perror("execv");
	_exit(127);
}

static void *start(void *arg)
{
	struct thread_opts *opts = (struct thread_opts *)arg;

	opts->status = fork_execv(opts->argc, opts->argv);
	if (opts->status == -1)
		perror("fork_execv");

	if (pthread_kill(opts->main_thread, SIGTERM))
		perror("ptrhead_kill");

	return &opts->status;
}

/* Under FreeBSD, there is no subtype option so this
   function actually sets the fsname */
static int add_default_subtype(const char *progname, struct fuse_args *args)
{
	int res;
	char *subtype_opt;

	const char *basename = strrchr(progname, '/');
	if (basename == NULL)
		basename = progname;
	else if (basename[1] != '\0')
		basename++;

	subtype_opt = (char *) malloc(strlen(basename) + 64);
	if (subtype_opt == NULL) {
		fuse_log(FUSE_LOG_ERR, "fuse: memory allocation failed\n");
		return -1;
	}
#ifdef __FreeBSD__
	sprintf(subtype_opt, "-ofsname=%s", basename);
#else
	sprintf(subtype_opt, "-osubtype=%s", basename);
#endif
	res = fuse_opt_add_arg(args, subtype_opt);
	free(subtype_opt);
	return res;
}

int sqlitefs_parse_cmdline(struct fuse_args *args,
			   struct sqlitefs_cmdline_opts *opts)
{
	memset(opts, 0, sizeof(struct sqlitefs_cmdline_opts));

	opts->base.max_idle_threads = 10;
	opts->file = NULL;

	if (fuse_opt_parse(args, opts, sqlitefs_opts, sqlitefs_opt_proc) == -1)
		return -1;

	/* *Linux*: if neither -o subtype nor -o fsname are specified,
	   set subtype to program's basename.
	   *FreeBSD*: if fsname is not specified, set to program's
	   basename. */
	if (!opts->base.nodefault_subtype)
		if (add_default_subtype(args->argv[0], args) == -1)
			return -1;

	return 0;
}

int sqlitefs_main(int argc, char *argv[], const struct fuse_operations *op,
		  size_t op_size, void *user_data)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct sqlitefs_cmdline_opts sqlitefs_opts;
	pthread_t t, main_thread = pthread_self();
	static struct thread_opts thread_opts;
	struct fuse_cmdline_opts *opts;
	sqlite3 *db = NULL;
	struct fuse *fuse;
	int res;

	opts = (struct fuse_cmdline_opts *)&sqlitefs_opts;
	if (sqlitefs_parse_cmdline(&args, &sqlitefs_opts) != 0) {
		fprintf(stderr, "%s: %s\n", "sqlitefs_parse_cmdline",
			"Invalid option arguments");
		return 1<<8;
	}

	if (opts->show_version) {
		printf("FUSE library version %s\n", PACKAGE_VERSION);
		fuse_lowlevel_version();
		res = 0;
		goto out1;
	}

	if (opts->show_help) {
		if(args.argv[0][0] != '\0')
			printf("usage: %s [options] <file> <mountpoint> [--] [command] [args]\n\n",
			       args.argv[0]);
		printf("FUSE options:\n");
		fuse_cmdline_help();
		fuse_lib_help(&args);
		res = 0;
		goto out1;
	}

	if (!opts->show_help &&
	    !sqlitefs_opts.file) {
		fuse_log(FUSE_LOG_ERR, "error: no file specified\n");
		res = 2<<8;
		goto out1;
	}

	if (sqlite3_open_v2(sqlitefs_opts.file, &db, SQLITE_OPEN_READWRITE,
			    NULL)) {
		__sqlite3_perror("sqlite3_open_v2", db);
		res = 2<<8;
		goto out1;
	}

	user_data = db;

	res = lost_found(db);
	if (res < 0) {
		__perror("lost_found", res);
		res = 2<<8;
		goto out1;
	} else if (res) {
		fprintf(stderr, "%i orphans found!\n", res);
		res = 0;
	}

	if (!opts->show_help &&
	    !opts->mountpoint) {
		fuse_log(FUSE_LOG_ERR, "error: no mountpoint specified\n");
		res = 2<<8;
		goto out1;
	}

	fuse = fuse_new(&args, op, op_size, user_data);
	if (fuse == NULL) {
		fprintf(stderr, "%s: %s\n", "fuse_new", "FUSE setup failed");
		res = 3<<8;
		goto out1;
	}

	if (fuse_mount(fuse,opts->mountpoint) != 0) {
		fprintf(stderr, "%s: %s\n", "fuse_mount", "Mounting failed");
		res = 4<<8;
		goto out2;
	}

	if (fuse_daemonize(opts->foreground) != 0) {
		fprintf(stderr, "%s: %s\n", "fuse_daemonize",
			"Failed to daemonize (detach from session)");
		res = 5<<8;
		goto out3;
	}

	if (sqlitefs_opts.command) {
		int argi;
		for (argi = 0; argi < argc; argi++)
			if (strcmp(argv[argi], sqlitefs_opts.command) == 0)
				break;

		/* hack: make the process get back to $PWD.
		 * The function fuse_daemonize() chdir to / even in foreground.
		 */
		if (chdir(getenv("PWD"))) {
			perror("chdir");
			res = 5<<8;
			goto out3;
		}

		if (setenv("mountpoint", opts->mountpoint, 1)) {
			perror("setenv");
			res = 5<<8;
			goto out3;
		}

		if (setenv("file", sqlitefs_opts.file, 1)) {
			perror("setenv");
			res = 5<<8;
			goto out3;
		}

		thread_opts.main_thread = main_thread;
		thread_opts.argv = &argv[argi];
		thread_opts.argc = argc - argi;
		if (pthread_create(&t, NULL, start, &thread_opts)) {
			perror("pthread_create");
			res = 5<<8;
			goto out3;
		}
	}

	struct fuse_session *se = fuse_get_session(fuse);
	if (fuse_set_signal_handlers(se) != 0) {
		fprintf(stderr, "%s: %s\n", "fuse_set_signal_handlers",
			"Failed to set up signal handlers");
		res = 6<<8;
		goto out3;
	}

	if (opts->singlethread)
		res = fuse_loop(fuse);
	else {
		struct fuse_loop_config loop_config;
		loop_config.clone_fd = opts->clone_fd;
		loop_config.max_idle_threads = opts->max_idle_threads;
		res = fuse_loop_mt(fuse, &loop_config);
	}
	if (res == SIGTERM)
		res = 0;
	if (res < 0) {
		fprintf(stderr, "fuse_loop%s: %s\n",
			opts->singlethread ? "" : "mt",
			"An error occured during the life of the file system");
		res = 7<<8;
	}

	fuse_remove_signal_handlers(se);
out3:
	fuse_unmount(fuse);
out2:
	fuse_destroy(fuse);
out1:
	free(sqlitefs_opts.file);
	free(opts->mountpoint);
	fuse_opt_free_args(&args);
	if (sqlitefs_opts.command && thread_opts.argv) {
		void *status;
		if (pthread_join(t, &status))
			perror("pthread_join");

		if (res == 0)
			res = *(int *)status;
	}
	if (db)
		sqlite3_close(db);

	if (WIFSIGNALED(res)) {
		fprintf(stderr, "%s\n", strsignal(WTERMSIG(res)));
		res = WTERMSIG(res)+128;
	} else if (WIFEXITED(res)) {
		res = WEXITSTATUS(res);
	}

	return res;
}

int main(int argc, char *argv[])
{
	int ret;

	if (__strncmp(basename(argv[0]), "mkfs.sqlitefs") == 0) {
		ret = mkfs(argv[1]);
		if (ret)
			__exit_perror(argv[1], -ret);

		return EXIT_SUCCESS;
	}

	if (__strncmp(basename(argv[0]), "fsck.sqlitefs") == 0) {
		ret = fsck(argv[1]);
		if (ret)
			__exit_perror(argv[1], -ret);

		return EXIT_SUCCESS;
	}

	return sqlitefs_main(argc, argv, &operations, sizeof(operations), NULL);
}
