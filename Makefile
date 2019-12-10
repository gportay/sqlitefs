#
#  Copyright (C) 2018-2019 Gaël PORTAY
#                2018      Savoir-Faire Linux Inc.
#
#  SPDX-License-Identifier: LGPL-2.1
#

override CFLAGS += $(shell pkg-config sqlite3 fuse --cflags)
override LDLIBS += $(shell pkg-config sqlite3 fuse --libs)

sqlitefs: override CFLAGS += -g -Wall -Wextra -Werror
sqlitefs:

mountpoint:
	mkdir -p $@

.PHONY: tests
tests: sqlitefs
	if ! bash tests.bash; then \
		mv fs.db failed.db; \
		echo -e "\e[1mNote:\e[0m The copy of the filesystem database is available at \`failed.db'." >&2; \
		exit 1; \
	fi

.PHONY: no-mount-tests
no-mount-tests: export NO_MOUNT=1
no-mount-tests:
	bash tests.bash

.PHONY: mount
mount: sqlitefs | mountpoint
	@echo "Note: You can run \$ cat mountpoint/autorun.ini"
	./sqlitefs -o nonempty -f mountpoint

.PHONY: umount
umount:
	fusermount -u mountpoint

.PHONY: clean
clean:
	rm -f sqlitefs fs.db failed.db

