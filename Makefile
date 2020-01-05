#
#  Copyright (C) 2018-2020 Gaël PORTAY
#                2018      Savoir-Faire Linux Inc.
#
#  SPDX-License-Identifier: LGPL-2.1
#

override CFLAGS += $(shell pkg-config sqlite3 fuse3 --cflags)
override LDLIBS += $(shell pkg-config sqlite3 fuse3 --libs)

all: sqlitefs mkfs.sqlitefs

.PHONY: doc
doc: sqlitefs.1.gz

mkfs.sqlitefs: | sqlitefs
	ln -sf sqlitefs $@

sqlitefs: override CFLAGS += -g -Wall -Wextra -Werror
sqlitefs:

fs.db: | mkfs.sqlitefs
	./mkfs.sqlitefs

mountpoint:
	mkdir -p $@

.PHONY: ci
ci: export EXIT_ON_ERROR = 1
ci: tests

.PHONY: tests
tests: sqlitefs fs.db
	if ! bash tests.bash; then \
		mv fs.db failed.db; \
		echo -e "\e[1mNote:\e[0m The copy of the filesystem database is available at \`failed.db'." >&2; \
		exit 1; \
	fi

.PHONY: no-mount-tests
no-mount-tests: export NO_MOUNT=1
no-mount-tests: fs.db
	bash tests.bash

.PHONY: mount
mount: sqlitefs | mountpoint fs.db
	@echo "Note: You can run \$$ cat mountpoint/autorun.inf"
	./sqlitefs -f mountpoint

.PHONY: umount
umount:
	fusermount -u mountpoint

.PHONY: clean
clean:
	rm -f sqlitefs mkfs.sqlitefs fs.db failed.db

PREPROCESS.c = $(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -E
%.i: %.c
	$(PREPROCESS.c) $(OUTPUT_OPTION) $<

%.1: %.1.adoc
	asciidoctor -b manpage -o $@ $<

%.gz: %
	gzip -c $^ >$@

