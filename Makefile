#
#  Copyright (C) 2018-2020 Gaël PORTAY
#                2018      Savoir-Faire Linux Inc.
#
#  SPDX-License-Identifier: LGPL-2.1
#

override CFLAGS += $(shell pkg-config sqlite3 fuse3 uuid --cflags)
override LDLIBS += $(shell pkg-config sqlite3 fuse3 uuid --libs)

all: sqlitefs mkfs.sqlitefs fsck.sqlitefs sqlitefs-ioctl

.SILENT: config.h
ifeq ($(VERSION),)
config.h: NAME = sqlitefs
config.h: VERSION = git-$(shell git describe --always --dirty)
endif
config.h:
	echo "/*" >$@.tmp
	echo " * Automatically generated file; DO NOT EDIT." >>$@.tmp
	echo " * sqlitfs $(VERSION) Configuration" >>$@.tmp
	echo " */" >>$@.tmp
	echo "" >>$@.tmp
	echo "#ifndef CONFIG_H" >>$@.tmp
	echo "#define CONFIG_H" >>$@.tmp
	echo "#define PACKAGE_NAME \"$(NAME)\"" >>$@.tmp
	echo "#define PACKAGE_VERSION \"$(VERSION)\"" >>$@.tmp
	if pkg-config --exists uuid; then \
		echo "#define HAVE_UUID 1" >>$@.tmp; \
	fi
	echo "#endif" >>$@.tmp
	mv $@.tmp $@

sqlitefs: config.h
sqlitefs: override CFLAGS += -DHAVE_CONFIG_H

.PHONY: doc
doc: sqlitefs.1.gz

mkfs.sqlitefs fsck.sqlitefs sqlitefs-ioctl: | sqlitefs
	ln -sf sqlitefs $@

sqlitefs: override CFLAGS += -g -Wall -Wextra -Werror
sqlitefs:

fs.db: | mkfs.sqlitefs
	./mkfs.sqlitefs $@ $(basename $(@F))

.SILENT: failed.db
failed.db:
	echo -e "\e[1mNote:\e[0m The filesystem database \`failed.db' is copied is the tests has failed!" >&2
	false

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
		echo    "      Run the command below to investigate:"; \
		echo    "      \$$ ./sqlitefs -v failed.db mountpoint -- /bin/sh"; \
		exit 1; \
	fi

.PHONY: no-mount-tests
no-mount-tests: export NO_MOUNT=1
no-mount-tests: fs.db
	bash tests.bash

.PHONY: mount
mount: sqlitefs | mountpoint fs.db
	./sqlitefs fs.db mountpoint

.PHONY: umount
umount:
	fusermount3 -u mountpoint

.PHONY: shell
shell: sqlitefs | mountpoint fs.db
	./sqlitefs fs.db mountpoint -- $(SHELL)

.PHONY: shell
failed-shell: sqlitefs | mountpoint failed.db
	./sqlitefs -v failed.db mountpoint -- $(SHELL)

.PHONY: verbose-shell
verbose-shell: sqlitefs | mountpoint fs.db
	./sqlitefs -v fs.db mountpoint -- $(SHELL)

.PHONY: debug-shell
debug-shell: sqlitefs | mountpoint fs.db
	./sqlitefs -d fs.db mountpoint -- $(SHELL)

.PHONY: valgrind-shell
valgrind-shell: sqlitefs | mountpoint fs.db
	valgrind ./sqlitefs fs.db mountpoint -- $(SHELL)

.PHONY: docker-shell
docker-shell: SHELL = /bin/bash
docker-shell: sqlitefs.iid
	docker run --rm --interactive --tty \
	           --privileged --cap-add SYS_ADMIN --cap-add MKNOD --device /dev/fuse \
	           --volume $$PWD:$$PWD \
	           --user $$UID:$$UID \
	           --workdir $$PWD \
	           --entrypoint $$SHELL \
		   sqlitefs

.PHONY: hotspot
hotspot: perf.data
	hotspot

.PHONY: perf
perf: perf.data
	perf report

perf.data: sqlitefs fs.db | mountpoint
	perf record --call-graph dwarf ./sqlitefs fs.db mountpoint -- rsync -av .git mountpoint/.

.PHONY: clean
clean:
	rm -f sqlitefs mkfs.sqlitefs fs.db failed.db perf.data

.PHONY: mrproper
mrproper: clean
	rm -f config.h

%.: SHELL = /bin/bash
%.iid: Dockerfile
	docker build --tag $* \
		     --iidfile $@ \
	             --build-arg user=$$USER \
	             --build-arg uid=$$UID \
	             --build-arg groups=$${GROUPS[0]} \
	             --build-arg home=$$HOME \
	             - <Dockerfile

PREPROCESS.c = $(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -E
%.i: %.c
	$(PREPROCESS.c) $(OUTPUT_OPTION) $<

%.1: %.1.adoc
	asciidoctor -b manpage -o $@ $<

%.gz: %
	gzip -c $^ >$@

