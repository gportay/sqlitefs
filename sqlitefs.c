/*
 *  Copyright (C) 2018-2020 Gaël PORTAY
 *                2018      Savoir-Faire Linux Inc.
 *
 *  SPDX-License-Identifier: LGPL-2.1
 */

#define FUSE_USE_VERSION 30

#ifdef HAVE_CONFIG_H
# include "config.h"
#else
const char VERSION[] = __DATE__ " " __TIME__;
#endif /* HAVE_CONFIG_H */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#include <libgen.h>
#include <fuse.h>
#include <sqlite3.h>

#include "hexdump.h"

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

#define __return_perror(s, e) do { \
	fprintf(stderr, "%s: %s\n", s, strerror(e)); \
	return -e; \
} while (0)

#define __exit_perror(s, e) do {\
	fprintf(stderr, "%s: %s\n", s, strerror(e)); \
	exit(EXIT_FAILURE); \
} while (0)

#define __data(s) s, sizeof(s) - 1

#define __sqlite3_perror(s, db) do { \
	fprintf(stderr, "%s: %s\n", s, sqlite3_errmsg(db)); \
} while (0)

static const char *mode(mode_t mode)
{
	if (S_ISREG(mode))
		return "regular file";

	if (S_ISDIR(mode))
		return "directory";

	if (S_ISBLK(mode))
		return "block special file";

	if (S_ISCHR(mode))
		return "character special file";

	if (S_ISFIFO(mode))
		return "fifo";

	if (S_ISLNK(mode))
		return "symbolic link";

	if (S_ISSOCK(mode))
		return "socket";

	return "unknown";
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
			  path, buf->st_size, buf->st_blocks, buf->st_blksize, mode(buf->st_mode),
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
};

static int readdir_cb(void *data, int argc, char **argv, char **colname)
{
	struct readdir_data *pdata = (struct readdir_data *)data;
	size_t len;
	int i;
	(void)colname;

	len = strlen(pdata->parent);
	for (i = 0; i < argc; i++) {
		if (strcmp(pdata->parent, argv[0]) == 0)
			continue;

		pdata->filler(pdata->buffer, &argv[0][len], NULL, 0);
	}

	return SQLITE_OK;
}

static int add_file(sqlite3 *db, const char *file, const char *parent,
		    const void *data, size_t datasize, const struct stat *st)
{
	char sql[BUFSIZ];
	int ret = -EIO;

	snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO files(path, parent, "
		 "data, st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, "
		 "st_rdev, st_size, st_blksize, st_blocks, st_atim_sec, "
		 "st_atim_nsec, st_mtim_sec, st_mtim_nsec, st_ctim_sec, "
		 "st_ctim_nsec) "
		 "VALUES(\"%s\", \"%s\", ?, %lu, %lu, %u, %lu, %u, %u, %lu, "
		 "%lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu);",
		 file, parent, st->st_dev, st->st_ino, st->st_mode,
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

static int add_symlink(sqlite3 *db, const char *linkname, const char *path,
		       const char *parent)
{
	struct stat st;
	char sql[BUFSIZ];
	char *e;
	int ret;

	if (!db || !linkname || !path || !parent)
		return -EINVAL;

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
	st.st_atime = time(NULL);
	st.st_mtime = time(NULL);
	st.st_ctime = time(NULL);

	ret = add_file(db, path, "/", NULL, 0, &st);
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

static int add_directory(sqlite3 *db, const char *file, const char *parent,
			 const struct stat *st)
{
	char sql[BUFSIZ];
	char *e;

	snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO files(path, parent, "
		 "st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, st_rdev, "
		 "st_size, st_blksize, st_blocks, st_atim_sec, st_atim_nsec, "
		 "st_mtim_sec, st_mtim_nsec, st_ctim_sec, st_ctim_nsec) "
		 "VALUES(\"%s\", \"%s\", %lu, %lu, %u, %lu, %u, %u, %lu, %lu, "
		 "%lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu);",
		 file, parent, st->st_dev, st->st_ino, st->st_mode,
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

static int __stat(const char *path, struct stat *st)
{
	sqlite3 *db = fuse_get_context()->private_data;
	struct getattr_data data = {
		errno = ENOENT,
		st = st,
	};
	char sql[BUFSIZ];
	char *e;
	int ret;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

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
				   "FROM files WHERE path = \"%s\";", path);
	ret = sqlite3_exec(db, sql, getattr_cb, &data, &e);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	if (data.error)
		return -data.error;

	fprintstat(stderr, path, st);

	return 0;
}

static ssize_t __pread(const char *path, char *buf, size_t bufsize,
		       off_t offset)
{
	sqlite3 *db = fuse_get_context()->private_data;
	int ret = -ENOENT;
	ssize_t size = 0;
	char sql[BUFSIZ];

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	snprintf(sql, sizeof(sql),
		 "SELECT data FROM files WHERE (path == \"%s\");", path);

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

	fhexdump(stderr, offset, buf, size);

	return size;
}

static ssize_t __pwrite(const char *path, const char *buf, size_t bufsize,
			off_t offset)
{
	sqlite3 *db = fuse_get_context()->private_data;
	ssize_t datasize = 0;
	void *data = NULL;
	struct stat st;
	int ret;

	ret = __stat(path, &st);
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

		s = __pread(path, data, st.st_size, 0);
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

		ret = add_file(db, path, "/", data, datasize, &st);
		if (ret)
			goto exit;

		goto exit;
	}

	ret = add_file(db, path, "/", buf, bufsize, &st);
	if (ret)
		return ret;

exit:
	if (data)
		free(data);

	if (ret)
		return ret;

	fhexdump(stderr, offset, buf, bufsize);

	return bufsize;
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
	return add_symlink(db, linkname, path, "/");
}

static int __readlink(sqlite3 *db, const char *path, char *buf, size_t len)
{
	struct readlink_data data = {
		errno = ENOENT,
		buf = buf,
		len = len,
	};
	char sql[BUFSIZ];
	char *e;
	int ret;

	if (!db || !path || !path || !buf)
		return -EINVAL;

	snprintf(sql, sizeof(sql), "SELECT "
					"path, "
					"linkname "
				   "FROM symlinks WHERE path = \"%s\";", path);
	ret = sqlite3_exec(db, sql, readlink_cb, &data, &e);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	if (data.error)
		return -data.error;

	fprintf(stderr, "%s\n", buf);

	return 0;
}

static int __mkdir(sqlite3 *db, const char *path, mode_t mode)
{
	struct stat st;

	if (!db || !path)
		return -EINVAL;

	memset(&st, 0, sizeof(struct stat));
	/* Ignored st.st_dev = 0; */
	/* Ignored st.st_ino = 0; */
	st.st_mode = S_IFDIR | mode;
	st.st_nlink = 2;
	st.st_uid = getuid();
	st.st_gid = getgid();
	/* Ignored st.st_blksize = 0; */
	st.st_atime = time(NULL);
	st.st_mtime = time(NULL);
	st.st_ctime = time(NULL);

	return add_directory(db, path, "/", &st);
}

static int mkfs(const char *path)
{
	char sql[BUFSIZ];
	struct stat st;
	sqlite3 *db;
	int exists;
	char *e;

	exists = stat(path, &st) == 0;
	if (exists)
		return -EEXIST;

	if (sqlite3_open(path, &db)) {
		fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errmsg(db));
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

	if (__mkdir(db, "/.Trash", 0755))
		goto error;

	memset(&st, 0, sizeof(struct stat));
	/* Ignored st.st_dev = 0; */
	/* Ignored st.st_ino = 0; */
	st.st_mode = S_IFREG | 0644;
	st.st_nlink = 1;
	st.st_uid = getuid();
	st.st_gid = getgid();
	/* Ignored st.st_blksize = 0; */
	st.st_atime = time(NULL);
	st.st_mtime = time(NULL);
	st.st_ctime = time(NULL);
	if (add_file(db, "/autorun.inf", "/",
		     __data("[autorun]\nlabel=sqlitefs\n"), &st))
		goto error;

	return 0;

error:
	sqlite3_close(db);
	return -EIO;
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
 * releasedir, fsyncdir, access, create, ftruncate, fgetattr, lock,
 * init and destroy are special purpose methods, without which a full
 * featured filesystem can still be implemented.
 *
 * Almost all operations take a path which can be of any length.
 *
 * Changed in fuse 2.8.0 (regardless of API version)
 * Previously, paths were limited to a length of PATH_MAX.
 *
 * See http://fuse.sourceforge.net/wiki/ for more information.  There
 * is also a snapshot of the relevant wiki pages in the doc/ folder.
 */

/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.	 The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
static int sqlitefs_getattr(const char *path, struct stat *st)
{
	return __stat(path, st);
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

/* Deprecated, use readdir() instead */
/* int (*getdir) (const char *, fuse_dirh_t, fuse_dirfil_t); */

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
static int sqlitefs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	sqlite3 *db = fuse_get_context()->private_data;
	struct stat st;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	memset(&st, 0, sizeof(struct stat));
	st.st_dev = rdev;
	/* Ignored st.st_ino = 0; */
	st.st_mode = mode;
	st.st_nlink = 1;
	st.st_uid = getuid();
	st.st_gid = getgid();
	/* Ignored st.st_blksize = 0; */
	st.st_atime = time(NULL);
	st.st_mtime = time(NULL);
	st.st_ctime = time(NULL);
	if (add_file(db, path, "/", NULL, 0, &st))
		return -EIO;

	return 0;
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

	return __unlink(db, path);
}

/** Rename a file */
static int sqlitefs_rename(const char *oldpath, const char *newpath)
{
	sqlite3 *db = fuse_get_context()->private_data;
	char sql[BUFSIZ];
	char *e;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

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

/** Create a hard link to a file */
static int sqlitefs_link(const char *oldpath, const char *newpath)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(oldpath: %s, newpath: %s)\n", __FUNCTION__,
		oldpath, newpath);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/** Create a symbolic link */
static int sqlitefs_symlink(const char *linkname, const char *path)
{
	sqlite3 *db = fuse_get_context()->private_data;

	return __symlink(db, linkname, path);
}

/** Change the permission bits of a file */
static int sqlitefs_chmod(const char *path, mode_t mode)
{
	sqlite3 *db = fuse_get_context()->private_data;
	char sql[BUFSIZ];
	char *e;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

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

/** Change the owner and group of a file */
static int sqlitefs_chown(const char *path, uid_t uid, gid_t gid)
{
	sqlite3 *db = fuse_get_context()->private_data;
	char sql[BUFSIZ];
	char *e;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

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

/** Change the size of a file */
static int sqlitefs_truncate(const char *path, off_t size)
{
	sqlite3 *db = fuse_get_context()->private_data;
	void *data = NULL;
	char sql[BUFSIZ];
	struct stat st;
	int ret;
	char *e;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	ret = __stat(path, &st);
	if (ret)
		return ret;

	data = malloc(size);
	ret = __pread(path, data, size, 0);
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

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/* int (*utime) (const char *, struct utimbuf *); */

/** File open operation
 *
 * No creation (O_CREAT, O_EXCL) and by default also no
 * truncation (O_TRUNC) flags will be passed to open(). If an
 * application specifies O_TRUNC, fuse first calls truncate()
 * and then open(). Only if 'atomic_o_trunc' has been
 * specified and kernel version is 2.6.24 or later, O_TRUNC is
 * passed on to open.
 *
 * Unless the 'default_permissions' mount option is given,
 * open should check if the operation is permitted for the
 * given flags. Optionally open may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to all file operations.
 *
 * Changed in version 2.2
 */
static int sqlitefs_open(const char *path, struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, fi: %p)\n",__FUNCTION__, path, fi);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.	 An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
int sqlitefs_read(const char *path, char *buf, size_t bufsize, off_t offset,
	     struct fuse_file_info *fi)
{
	(void)fi;

	return __pread(path, buf, bufsize, offset);
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.	 An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
static int sqlitefs_write(const char *path, const char *buf, size_t bufsize,
			  off_t offset, struct fuse_file_info *fi)
{
	(void)fi;

	return __pwrite(path, buf, bufsize, offset);
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.	 It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
static int sqlitefs_release(const char *path, struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, fi: %p)\n",__FUNCTION__, path, fi);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
static int sqlitefs_fsync(const char *path, int datasync,
			  struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, datasync: %i, fi: %p)\n", __FUNCTION__,
		path, datasync, fi);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */
static int sqlitefs_readdir(const char *path, void *buffer,
			    fuse_fill_dir_t filler, off_t offset,
			    struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	struct readdir_data data = {
		.parent = path,
		.buffer = buffer,
		.filler = filler,
	};
	char sql[BUFSIZ];
	char *e;
	int ret;
	(void)offset;
	(void)fi;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	filler(buffer, ".", NULL, 0);
	filler(buffer, "..", NULL, 0);

	snprintf(sql, sizeof(sql),
		 "SELECT path FROM files WHERE parent = \"%s\";", path);
	ret = sqlite3_exec(db, sql, readdir_cb, &data, &e);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EACCES;
	}

	return 0;
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
/* void *(*init) (struct fuse_conn_info *conn); */

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
static void sqlitefs_destroy(void *ptr)
{
	sqlite3 *db = (sqlite3 *)ptr;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return;
	}

	sqlite3_close(db);
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
static int sqlitefs_access(const char *path, int mask)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, mask: %i)\n", __FUNCTION__, path, mask);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
static int sqlitefs_create(const char *path, mode_t mode,
			   struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, mode: %i, fi: %p)\n", __FUNCTION__, path,
		mode, fi);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
static int sqlitefs_ftruncate(const char *path, off_t off,
			      struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, off: %li, fi: %p)\n", __FUNCTION__, path,
		off, fi);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
static int sqlitefs_fgetattr(const char *path, struct stat *buf,
			     struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, buf: %p, fi: %p)\n", __FUNCTION__, path,
		buf, fi);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

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
 *
 * Introduced in version 2.6
 */
static int sqlitefs_lock(const char *path, struct fuse_file_info *fi, int cmd,
			 struct flock *lock)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, fi: %p, cmd: %i, lock: %p)\n",
		__FUNCTION__, path, fi, cmd, lock);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * This supersedes the old utime() interface.  New applications
 * should use this.
 *
 * See the utimensat(2) man page for details.
 *
 * Introduced in version 2.6
 */
static int sqlitefs_utimens(const char *path, const struct timespec tv[2])
{
	sqlite3 *db = fuse_get_context()->private_data;
	char sql[BUFSIZ];
	char *e;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	snprintf(sql, sizeof(sql), "UPDATE files SET "
					"st_mtim_sec=%lu, "
					"st_mtim_nsec=%lu, "
					"st_ctim_sec=%lu, "
					"st_ctim_nsec=%lu "
				   "WHERE path=\"%s\";",
		 tv[0].tv_sec, tv[0].tv_nsec, tv[1].tv_sec, tv[1].tv_nsec,
		 path);

	if (sqlite3_exec(db, sql, NULL, 0, &e) != SQLITE_OK) {
		fprintf(stderr, "sqlite3_exec: %s\n", e);
		sqlite3_free(e);
		return -EIO;
	}

	return 0;
}

/**
 * Map block index within file to block index within device
 *
 * Note: This makes sense only for block device backed filesystems
 * mounted with the 'blkdev' option
 *
 * Introduced in version 2.6
 */
static int sqlitefs_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, blocksize: %lu, idx: %p)\n", __FUNCTION__,
		path, blocksize, idx);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

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
 * Introduced in version 2.8
 */
static int sqlitefs_ioctl(const char *path, int cmd, void *arg,
			  struct fuse_file_info *fi, unsigned int flags,
			  void *data)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, cmd: %i, arg: %p, fi: %p, flags: %u, data: %p)\n",
		__FUNCTION__, path, cmd, arg, fi, flags, data);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

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
 *
 * Introduced in version 2.8
 */
static int sqlitefs_poll(const char *path, struct fuse_file_info *fi,
			 struct fuse_pollhandle *ph, unsigned *reventsp)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, fi: %p, ph: %p, reventsp: %p)\n",
		__FUNCTION__, path, fi, ph, reventsp);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

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
 *
 * Introduced in version 2.9
 */
static int sqlitefs_flock(const char *path, struct fuse_file_info *fi, int op)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, fi: %p, op: %i)\n", __FUNCTION__, path,
		fi, op);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

/**
 * Allocates space for an open file
 *
 * This function ensures that required space is allocated for specified
 * file.  If this function returns success then any subsequent write
 * request to specified range is guaranteed not to fail because of lack
 * of space on the file system media.
 *
 * Introduced in version 2.9.1
 */
static int sqlitefs_fallocate(const char *path, int mode, off_t off, off_t len,
			      struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;

	fprintf(stderr, "%s(path: %s, mode: %x, off: %li, len: %li, fi: %p)\n",
		__FUNCTION__, path, mode, off, len, fi);

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s: %s\n", __func__, strerror(ENOSYS));
	return -ENOSYS;
}

static struct fuse_operations operations = {
	.getattr = sqlitefs_getattr,
	.readlink = sqlitefs_readlink,
	/* .getdir */
	.mknod = sqlitefs_mknod,
	.mkdir = sqlitefs_mkdir,
	.unlink = sqlitefs_unlink,
	.rmdir = sqlitefs_rmdir,
	.symlink = sqlitefs_symlink,
	.rename = sqlitefs_rename,
	.link = sqlitefs_link,
	.chmod = sqlitefs_chmod,
	.chown = sqlitefs_chown,
	.truncate = sqlitefs_truncate,
	/* .utime */
	.open = sqlitefs_open,
	.read = sqlitefs_read,
	.write = sqlitefs_write,
	.release = sqlitefs_release,
	.fsync = sqlitefs_fsync,
	/* .opendir */
	.readdir = sqlitefs_readdir,
	/* .releasedir */
	/* .fsyncdir */
	/* .init */
	.destroy = sqlitefs_destroy,
	.access = sqlitefs_access,
	.create = sqlitefs_create,
	.ftruncate = sqlitefs_ftruncate,
	.fgetattr = sqlitefs_fgetattr,
	.lock = sqlitefs_lock,
	.utimens = sqlitefs_utimens,
	.bmap = sqlitefs_bmap,
	.ioctl = sqlitefs_ioctl,
	.poll = sqlitefs_poll,
	/* .write_buf */
	/* .read_buf */
	.flock = sqlitefs_flock,
	.fallocate = sqlitefs_fallocate,
};

int main(int argc, char *argv[])
{
	sqlite3 *db;

	if (__strncmp(basename(argv[0]), "mkfs.sqlitefs") == 0) {
		int err = mkfs("fs.db");
		if (err)
			__exit_perror("fs.db", -err);

		return EXIT_SUCCESS;
	}

	if (sqlite3_open_v2("fs.db", &db, SQLITE_OPEN_READWRITE, NULL)) {
		fprintf(stderr, "sqlite3_open_v2: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		__exit_perror("fs.db", EIO);
	}

	return fuse_main(argc, argv, &operations, db);
}
