#!/bin/bash
#
# Copyright (C) 2019 Gaël PORTAY
#
# SPDX-License-Identifier: LGPL-2.1
#

set -e
set -o pipefail

run() {
	id="$((id+1))"
	test="#$id: $*"
	echo -e "\e[1mRunning $test...\e[0m"
}

todo() {
	todo="$((todo+1))"
	echo -e "\e[1m$test: \e[34m[TODO]\e[0m"
}

ok() {
	ok="$((ok+1))"
	echo -e "\e[1m$test: \e[32m[OK]\e[0m"
}

ko() {
	ko="$((ko+1))"
	echo -e "\e[1m$test: \e[31m[KO]\e[0m"
	if [[ $EXIT_ON_ERROR ]]
	then
		exit 1
	fi
}

result() {
	exitcode="$?"
	trap - 0
	if mountpoint --quiet mountpoint/
	then
		fusermount -u mountpoint/ || echo "Oops !" >&2
	fi

	if [[ $todo ]]
	then
		echo -e "\e[1m\e[34m$todo test(s) to do!\e[0m" >&2
	fi

	if [[ $ok ]]
	then
		echo -e "\e[1m\e[32m$ok test(s) succeed!\e[0m"
	fi

	if [[ $ko ]]
	then
		echo -e "\e[1mError: \e[31m$ko test(s) failed!\e[0m" >&2
	fi

	if [[ $exitcode -ne 0 ]] && [[ $ko -eq 0 ]]
	then
		echo -e "\e[1;31mExited!\e[0m" >&2
	fi

	exit "$exitcode"
}

PATH="$PWD:$PATH"
if mountpoint --quiet mountpoint/
then
	echo "Error: Busy!"
	echo "       $ fusermount -u mountpoint/"
	exit 1
fi >&2
trap result 0 SIGINT
if [[ ! -d mountpoint/ ]]
then
	mkdir -p mountpoint/
fi
if [[ $NO_MOUNT ]]
then
	todo() {
		ko
	}

	mkdir -p mountpoint/.lost+found
else
	sqlitefs -f fs.db mountpoint/ &
	while ! mountpoint --quiet mountpoint
	do
		sleep 0.1
	done
fi

run "Echo label"
if echo -n "test" >mountpoint/.super/label &&
   cat mountpoint/.super/label | tee /dev/stderr | md5sum | \
   grep -q '^098f6bcd4621d373cade4e832627b4f6  -$'
then
	ok
else
	ko
fi
echo

run "Get filesystem label"
if sqlitefs-ioctl getfslabel mountpoint | tee /dev/stderr | \
   grep -q 'test'
then
	ok
else
	ko
fi
echo

run "Set filesystem label"
if sqlitefs-ioctl setfslabel mountpoint "fs"
then
	ok
else
	ko
fi
echo

run "Get filesystem label"
if sqlitefs-ioctl getfslabel mountpoint | tee /dev/stderr | \
   grep -q 'fs'
then
	ok
else
	ko
fi
echo

run "Set flags"
if sqlitefs-ioctl setflags mountpoint/.super/version 0
then
	ok
else
	ko
fi
echo

run "Get flags"
if sqlitefs-ioctl getflags mountpoint/.super/version | tee /dev/stderr | \
   grep -q '0'
then
	ok
else
	ko
fi
echo

run "List directory content"
if ls -1a mountpoint | tee /dev/stderr | \
   grep '.lost+found'
then
	ok
else
	ko
fi
echo

run "Test directory existance"
if test -d mountpoint/.lost+found
then
	ok
else
	ko
fi
echo

run "Touch file"
if touch mountpoint/tmp.sh &&
   test -e mountpoint/tmp.sh
then
	ok
else
	ko
fi
echo

run "Dump extended attributes"
if getfattr -d -m - mountpoint/tmp.sh | tee /dev/stderr | md5sum | tee /dev/stderr |
   grep -q '^d41d8cd98f00b204e9800998ecf8427e  -$'
then
	ok
else
	ko
fi
echo

run "Get non existing extended attribute"
if ! getfattr -n sqlitesfs.foo mountpoint/tmp.sh| tee /dev/stderr |
     grep -v "# file: mountpoint/tmp.sh"
then
	ok
else
	ko
fi
echo

run "Set extended attribute"
if setfattr -n sqlitesfs.foo -v 1 mountpoint/tmp.sh
then
	ok
else
	ko
fi
echo

run "Get extended attribute"
if getfattr -n sqlitesfs.foo mountpoint/tmp.sh | tee /dev/stderr |
   grep -q "# file: mountpoint/tmp.sh"
then
	ok
else
	ko
fi
echo

run "Dump extended attributes"
if getfattr -d -m - mountpoint/tmp.sh | tee /dev/stderr |
   grep -q "# file: mountpoint/tmp.sh"
then
	ok
else
	ko
fi
echo

run "Remove extended attribute"
if setfattr -x sqlitefs.foo mountpoint/tmp.sh
then
	ok
else
	ko
fi
echo

run "Get removed extended attribute"
if ! getfattr -n sqlitesfs.foo mountpoint/tmp.sh | tee /dev/stderr | md5sum | tee /dev/stderr |
   grep -q '^d41d8cd98f00b204e9800998ecf8427e  -$'
then
	ok
else
	ko
fi
echo

run "Dump extended attributes"
if getfattr -d -m - mountpoint/tmp.sh | tee /dev/stderr |
   grep -q "# file: mountpoint/tmp.sh"
then
	ok
else
	ko
fi
echo

run "Change ownership"
if fakeroot -- /bin/sh -c '
   chown root:root mountpoint/tmp.sh  &&
   stat --printf="%U:%G\n" mountpoint/tmp.sh | tee /dev/stderr |
   grep -q "^root:root\$"
   '
then
	ok
else
	ko
fi
echo

run "Change mode"
if chmod 755 mountpoint/tmp.sh &&
   stat --printf="%a\n" mountpoint/tmp.sh | tee /dev/stderr |
   grep -q '^755$'
then
	ok
else
	ko
fi
echo

run "Echo in file"
if echo "#!/bin/sh" >mountpoint/tmp.sh &&
   cat mountpoint/tmp.sh | tee /dev/stderr | md5sum | tee /dev/stderr |
   grep -q '^3e2b31c72181b87149ff995e7202c0e3  -$'
then
	ok
else
	ko
fi
echo

run "Echo in file (append)"
if echo "echo 'Hello, World!'" >>mountpoint/tmp.sh &&
   cat mountpoint/tmp.sh | tee /dev/stderr | md5sum | tee /dev/stderr |
   grep -q '^afe98cfb03203f86864ac600228e28b3  -$'
then
	ok
else
	ko
fi
echo

run "Move file"
if mv mountpoint/tmp.sh mountpoint/hello-world.sh &&
   ! test -e mountpoint/tmp.sh &&
   test -e mountpoint/hello-world.sh
then
	ok
else
	ko
fi
echo

run "Remove file"
if rm mountpoint/hello-world.sh &&
   ! test -e mountpoint/hello-world.sh
then
	ok
else
	ko
fi
echo

run "Copy file (to top-level directory)"
if cp README.md mountpoint/ &&
   test -e mountpoint/README.md
then
	ok
else
	ko
fi
echo

run "Rename file to existing file (from top-level directory)"
if cp README.md mountpoint/README.md.new &&
   test -e mountpoint/README.md.new &&
   mv mountpoint/README.md.new mountpoint/README.md &&
   ! test -e mountpoint/README.md.new &&
   test -e mountpoint/README.md
then
	ok
else
	ko
fi
echo

run "Remove file (from top-level directory)"
if rm mountpoint/README.md &&
   ! test -e mountpoint/README.md
then
	ok
else
	ko
fi
echo

run "Make directory (to top-level directory)"
if mkdir -p mountpoint/dir &&
   test -d mountpoint/dir
then
	ok
else
	ko
fi
echo

run "Copy file (to none-top-level directory)"
if cp README.md mountpoint/dir &&
   test -e mountpoint/dir/README.md
then
	ok
else
	ko
fi
echo

run "Remove file (from none-top-level directory)"
if rm mountpoint/dir/README.md &&
   ! test -e mountpoint/dir/README.md
then
	ok
else
	ko
fi
echo

run "Make directory (to none-top-level directory)"
if mkdir -p mountpoint/dir/dir2 &&
   test -d mountpoint/dir/dir2
then
	ok
else
	ko
fi
echo

run "Remove directory (from none-top-level directory)"
if rmdir mountpoint/dir/dir2 &&
   ! test -d mountpoint/dir/dir2
then
	ok
else
	ko
fi
echo

run "Do not make an orphan directory"
if mkdir -p mountpoint/dir/subdir/orphan &&
   test -d mountpoint/dir/subdir/orphan &&
   ! rmdir mountpoint/dir/subdir &&
   rmdir mountpoint/dir/subdir/orphan &&
   rmdir mountpoint/dir/subdir
then
	ok
else
	ko
fi
echo

run "Remove directory (from top-level directory)"
if rmdir mountpoint/dir &&
   ! test -d mountpoint/dir
then
	ok
else
	ko
fi
echo

run "Make symbolic link"
if ln -sf .Trash mountpoint/symlink &&
   test -L mountpoint/symlink
then
	ok
else
	ko
fi
echo

run "Read symbolic link"
if readlink mountpoint/symlink | tee /dev/stderr |
   grep -q '^.Trash$'
then
	ok
else
	ko
fi
echo

run "List symbolic link"
if ls -l mountpoint/symlink | tee /dev/stderr |
   grep -q "^lrwxrwxrwx 1 $USER $USER 6 .* mountpoint/symlink -> .Trash\$"
then
	ok
else
	ko
fi
echo

run "Move symlink"
if mv mountpoint/symlink mountpoint/trash &&
   ! test -L mountpoint/symlink &&
   test -L mountpoint/trash
then
	ok
else
	ko
fi
echo

run "Read symbolic link"
if readlink mountpoint/trash | tee /dev/stderr |
   grep -q '^.Trash$'
then
	ok
else
	ko
fi
echo

run "List symbolic link"
if ls -l mountpoint/trash | tee /dev/stderr |
   grep -q "^lrwxrwxrwx 1 $USER $USER 6 .* mountpoint/trash -> .Trash\$"
then
	ok
else
	ko
fi
echo

run "Remove symlink"
if rm mountpoint/trash &&
   ! test -L mountpoint/trash
then
	ok
else
	ko
fi
echo
