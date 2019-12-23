#
#  Copyright (C) 2018 Savoir-Faire Linux Inc.
#                2018 Gaël PORTAY
#
#  Authors:
#      Gaël PORTAY <gael.portay@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 2.1 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

override CFLAGS += $(shell pkg-config sqlite3 fuse --cflags)
override LDLIBS += $(shell pkg-config sqlite3 fuse --libs)

sqlitefs: override CFLAGS += -g -Wall -Wextra -Werror -Wno-error=unused-function -Wno-error=unused-parameter -Wno-error=unused-variable
sqlitefs:

mountpoint:
	mkdir -p $@

.PHONY: tests
tests: sqlitefs | mountpoint
	@echo "Note: You can run \$ cat mountpoint/autorun.ini"
	./sqlitefs -d mountpoint

.PHONY: clean
clean:
	rm -f sqlitefs fs.db

