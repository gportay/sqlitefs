/*
 *  Copyright (C) 2018 Savoir-Faire Linux Inc.
 *                2018 Gaël PORTAY
 *
 *  Authors:
 *       Gaël PORTAY <gael.portay@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include <sys/xattr.h>

#include <fuse.h>
#include <sqlite3.h>

#include "hexdump.h"

#define __max(a,b) ({ \
	__typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a > _b ? _a : _b; \
})

#define __min(a,b) ({ \
	__typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a < _b ? _a : _b; \
})

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
	(void)argv;
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
		    void *data, size_t datasize, const struct stat *st)
{
	char sql[BUFSIZ];

	snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO files(path, parent, "
		 "data, st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, "
		 "st_rdev, st_size, st_blksize, st_blocks, st_atim_sec, "
		 "st_atim_nsec, st_mtim_sec, st_mtim_nsec, st_ctim_sec, "
		 "st_ctim_nsec) "
		 "VALUES(\"%s\", \"%s\", ?, %lu, %lu, %u, %lu, %u, %u, %lu, "
		 "%lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu);",
		 file, parent, st->st_dev, st->st_ino, st->st_mode,
		 st->st_nlink, st->st_uid, st->st_gid, st->st_rdev, st->st_size,
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

		break;
	}

exit:
	return 0;
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
		return 1;
	}

	return 0;
}

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
static int sqlitefs_getattr(const char *path, struct stat *st)
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
		return -EACCES;
	}

	if (data.error) {
		return -data.error;
	}

	fprintstat(stderr, path, st);

	return 0;
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.	If the linkname is too long to fit in the
 * buffer, it should be truncated.	The return value should be 0
 * for success.
 */
static int squasfs_readlink(const char *path, char *buf, size_t bufsize)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)path;
	(void)buf;
	(void)bufsize;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	return -1;
}

/* Deprecated, use readdir() instead */
/* int (*getdir) (const char *, fuse_dirh_t, fuse_dirfil_t); */

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
int sqlitefs_mknod(const char *path, mode_t mode, dev_t dev)
{
	sqlite3 *db = fuse_get_context()->private_data;
	struct stat st;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s(path: %s, mode: %x, dev: %li)\n", __FUNCTION__,
		path, mode, dev);

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
	st.st_size = 0;
	if (add_file(db, path, "/", "", 0, &st)) {
		sqlite3_close(db);
		return -EIO;
	}

	return 0;
}

/** Change the permission bits of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 */
#if 0
static int sqlitefs_chmod(const char *path, mode_t mode,
			  struct fuse_file_info *fi)
{
	fprintf(stderr, "%s(path: %s, mode: %x, fi: %p)\n", __FUNCTION__, path,
		mode, fi);

	return 0;
}
#else
static int sqlitefs_chmod(const char *path, mode_t mode)
{
	fprintf(stderr, "%s(path: %s, mode: %x)\n", __FUNCTION__, path, mode);

	return 0;
}
#endif

/** Change the owner and group of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
#if 0
static int sqlitefs_chown(const char *path, uid_t uid, gid_t gid,
			  struct fuse_file_info *fi)
{
	fprintf(stderr, "%s(path: %s, uid: %i, gid: %i, fi: %p)\n",
		__FUNCTION__, path, uid, gid, fi);

	return 0;
}
#else
static int sqlitefs_chown(const char *path, uid_t uid, gid_t gid)
{
	fprintf(stderr, "%s(path: %s, uid: %i, gid: %i)\n", __FUNCTION__, path,
		uid, gid);

	return 0;
}
#endif

/** Change the size of a file
 *
 * `fi` will always be NULL if the file is not currenlty open, but
 * may also be NULL if the file is open.
 *
 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
 * expected to reset the setuid and setgid bits.
 */
#if 0
static int sqlitefs_truncate(const char *path, off_t size,
			     struct fuse_file_info *fi)
{
	fprintf(stderr, "%s(path: %s, size: %li, fi: %p)\n", __FUNCTION__, path,
		size, fi);

	return 0;
}
#else
static int sqlitefs_truncate(const char *path, off_t size)
{
	fprintf(stderr, "%s(path: %s, size: %li)\n", __FUNCTION__, path, size);

	return 0;
}
#endif

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
 */
static int sqlitefs_open(const char *path, struct fuse_file_info *fuse)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)path;
	(void)fuse;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	fprintf(stderr, "%s(path: %s, fuse: %p)\n", __FUNCTION__, path, fuse);

	return 0;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.	 An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 */
int sqlitefs_read(const char *path, char *buf, size_t bufsize, off_t offset,
	     struct fuse_file_info *fi)
{
	sqlite3 *db = fuse_get_context()->private_data;
	char sql[BUFSIZ];
	int size = 0;
	(void)bufsize;
	(void)fi;

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
			goto exit;
		}

		if (sqlite3_step(stmt) != SQLITE_ROW) {
			__sqlite3_perror("sqlite3_step", db);
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
			continue;
		}

		break;
	}

	fhexdump(stderr, offset, buf, size);

exit:
	return size;
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
 */
static int sqlitefs_release(const char *path, struct fuse_file_info *fi)
{
	fprintf(stderr, "%s(path: %s, fi: %p)\n", __FUNCTION__, path, fi);

	return 0;
}

/** Set extended attributes */
static int sqlitefs_setxattr(const char *path, const char *name,
			     const char *value, size_t size, int flags)
{
	fprintf(stderr, "%s(path: %s, name: %s, value: %s, size: %li, flags: %i)\n",
		__FUNCTION__, path, name, value, size, flags);

	return 0;
}

/** Get extended attributes */
static int sqlitefs_getxattr(const char *path, const char *name, char *value,
			     size_t size)
{
	fprintf(stderr, "%s(path: %s, name: %s, value: %s, size: %li)\n",
		__FUNCTION__, path, name, value, size);

	return 0;
}

/** List extended attributes */
static int sqlitefs_listxattr(const char *path, char *list, size_t size)
{
	fprintf(stderr, "%s(path: %s, list: %s, size: %li)\n", __FUNCTION__,
		path, list, size);

	return 0;
}

/** Remove extended attributes */
static int sqlitefs_removexattr(const char *path, const char *name)
{
	fprintf(stderr, "%s(path: %s, name: %s)\n", __FUNCTION__, path, name);

	return 0;
}

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
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 */
static int sqlitefs_create(const char *path, mode_t mode,
			   struct fuse_file_info *f)
{
	(void)path;
	(void)mode;
	(void)f;
	sqlite3 *db = fuse_get_context()->private_data;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	return -1;
}

/** Create a directory
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 * */
static int sqlitefs_mkdir(const char *path, mode_t mode)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)path;
	(void)mode;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	return -1;
}

/** Remove a file */
static int sqlitefs_unlink(const char *path)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)path;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		errno = EINVAL;
		return -1;
	}

	return -1;
}

/** Remove a directory */
static int sqlitefs_rmdir(const char *path)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)path;

	if (!db) {
		errno = EINVAL;
		return -1;
	}

	return -1;
}

/** Create a symbolic link */
static int sqlitefs_symlink(const char *path1, const char *path2)
{
	sqlite3 *db = fuse_get_context()->private_data;
	(void)path1;
	(void)path2;

	if (!db) {
		fprintf(stderr, "%s: Invalid context\n", __FUNCTION__);
		return -EINVAL;
	}

	return -EIO;
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
static void *sqlitefs_init(struct fuse_conn_info *conn)
{
	char sql[BUFSIZ];
	struct stat st;
	sqlite3 *db;
	int exists;
	char *e;
	(void)conn;

	exists = stat("fs.db", &st) == 0;

	if (sqlite3_open("fs.db", &db)) {
		fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return NULL;
	}

	if (!exists) {
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
			sqlite3_close(db);
			return NULL;
		}

		memset(&st, 0, sizeof(struct stat));
		/* Ignored st.st_dev = 0; */
		/* Ignored st.st_ino = 0; */
		st.st_mode = S_IFDIR | 0755;
		st.st_nlink = 2;
		st.st_uid = getuid();
		st.st_gid = getgid();
		/* Ignored st.st_blksize = 0; */
		st.st_atime = time(NULL);
		st.st_mtime = time(NULL);
		st.st_ctime = time(NULL);

		if (add_directory(db, "/", "/", &st)) {
			sqlite3_close(db);
			return NULL;
		}

		if (add_directory(db, "/.Trash", "/", &st)) {
			sqlite3_close(db);
			return NULL;
		}

		st.st_mode = S_IFREG | 0644;
		st.st_nlink = 1;
		st.st_size = 1024;
		if (add_file(db, "/autorun.inf", "/",
			     __data("[autorun]\nlabel=sqlitefs\n"), &st)) {
			sqlite3_close(db);
			return NULL;
		}
	}

	return db;
}

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

static struct fuse_operations operations = {
	.getattr = sqlitefs_getattr,
	.mknod = sqlitefs_mknod,
//	.unlink = sqlitefs_unlink,
//	.rmdir = sqlitefs_rmdir,
//	.symlink = sqlitefs_symlink,
	.open = sqlitefs_open,
	.read = sqlitefs_read,
	.release = sqlitefs_release,
	.chmod = sqlitefs_chmod,
	.chown = sqlitefs_chown,
	.truncate = sqlitefs_truncate,
//	.utimens = sqlitefs_utimens,
	.setxattr = sqlitefs_setxattr,
	.readdir = sqlitefs_readdir,
//	.create = sqlitefs_create,
	.init = sqlitefs_init,
	.destroy = sqlitefs_destroy,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &operations, NULL);
}
