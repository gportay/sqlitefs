#
#  Copyright (C) 2018 Savoir-Faire Linux Inc.
#                2018 Gaël PORTAY
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
tests: sqlitefs | mountpoint
	@echo "Note: You can run \$ cat mountpoint/autorun.ini"
	./sqlitefs -f mountpoint

.PHONY: clean
clean:
	rm -f sqlitefs fs.db

