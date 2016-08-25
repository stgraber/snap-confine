/*
 * Copyright (C) 2015 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"

void die(const char *msg, ...)
{
	va_list va;
	va_start(va, msg);
	vfprintf(stderr, msg, va);
	va_end(va);

	if (errno != 0) {
		perror(". errmsg");
	} else {
		fprintf(stderr, "\n");
	}
	exit(1);
}

bool error(const char *msg, ...)
{
	va_list va;
	va_start(va, msg);
	vfprintf(stderr, msg, va);
	va_end(va);

	return false;
}

void debug(const char *msg, ...)
{
	if (getenv("SNAP_CONFINE_DEBUG") == NULL)
		return;

	va_list va;
	va_start(va, msg);
	fprintf(stderr, "DEBUG: ");
	vfprintf(stderr, msg, va);
	fprintf(stderr, "\n");
	va_end(va);
}

void write_string_to_file(const char *filepath, const char *buf)
{
	debug("write_string_to_file %s %s", filepath, buf);
	FILE *f = fopen(filepath, "w");
	if (f == NULL)
		die("fopen %s failed", filepath);
	if (fwrite(buf, strlen(buf), 1, f) != 1)
		die("fwrite failed");
	if (fflush(f) != 0)
		die("fflush failed");
	if (fclose(f) != 0)
		die("fclose failed");
}

int must_snprintf(char *str, size_t size, const char *format, ...)
{
	int n = -1;

	va_list va;
	va_start(va, format);
	n = vsnprintf(str, size, format, va);
	va_end(va);

	if (n < 0 || n >= size)
		die("failed to snprintf %s", str);

	return n;
}

void mkpath(const char *const path)
{
	// If asked to create an empty path, return immediately.
	if (strlen(path) == 0) {
		return;
	}
	// We're going to use strtok_r, which needs to modify the path, so
	// we'll make a copy of it.
	char *path_copy = strdup(path);
	if (path_copy == NULL) {
		die("failed to create user data directory");
	}
	// Open flags to use while we walk the user data path:
	// - Don't follow symlinks
	// - Don't allow child access to file descriptor
	// - Only open a directory (fail otherwise)
	int open_flags = O_NOFOLLOW | O_CLOEXEC | O_DIRECTORY;

	// We're going to create each path segment via openat/mkdirat calls
	// instead of mkdir calls, to avoid following symlinks and placing the
	// user data directory somewhere we never intended for it to go. The
	// first step is to get an initial file descriptor.
	int fd = AT_FDCWD;
	if (path_copy[0] == '/') {
		fd = open("/", open_flags);
		if (fd < 0) {
			free(path_copy);
			die("failed to create user data directory");
		}
	}
	// strtok_r needs a pointer to keep track of where it is in the string.
	char *path_walker;

	// Initialize tokenizer and obtain first path segment.
	char *path_segment = strtok_r(path_copy, "/", &path_walker);
	while (path_segment) {
		// Try to create the directory. It's okay if it already
		// existed, but any other error is fatal.
		if (mkdirat(fd, path_segment, 0755) < 0 && errno != EEXIST) {
			close(fd);	// we die regardless of return code
			free(path_copy);
			die("failed to create user data directory");
		}
		// Open the parent directory we just made (and close the
		// previous one) so we can continue down the path.
		int previous_fd = fd;
		fd = openat(fd, path_segment, open_flags);
		if (close(previous_fd) != 0) {
			free(path_copy);
			die("could not close path segment");
		}
		if (fd < 0) {
			free(path_copy);
			die("failed to create user data directory");
		}
		// Obtain the next path segment.
		path_segment = strtok_r(NULL, "/", &path_walker);
	}

	// Close the descriptor for the final directory in the path.
	if (close(fd) != 0) {
		free(path_copy);
		die("could not close final directory");
	}

	free(path_copy);
}
