# sqlitefs(1)

A SQLite file-system in user-space.

## TL;DR

SQLiteFS is a [FUSE] module that stores files in a database backed by [SQLite].

It does the glue between the [libfuse callbacks] and the [SQLite API].

## AUTHOR

Written by Gaël PORTAY *gael.portay@gmail.com*

## COPYRIGHT

Copyright (C) 2018-2020 Gaël PORTAY

Copyright (C) 2018 Savoir-Faire Linux Inc.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation, either version 2.1 of the License, or (at your option) any
later version.

## SEE ALSO

sqlite3(1), fusermount(1), mount.fuse(8)

[FUSE]: https://www.kernel.org/doc/html/latest/filesystems/fuse.html
[libfuse callbacks]: http://libfuse.github.io/doxygen/index.html
[SQLite]: https://www.sqlite.org/index.html
[SQLite API]: https://www.sqlite.org/capi3ref.html
