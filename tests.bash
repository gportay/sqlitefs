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
		exit 1
	fi
}

PATH="$PWD:$PATH"
if mountpoint --quiet mountpoint/
then
	echo "Error: Busy!"
	echo "       $ fusermount -u mountpoint/"
	exit 1
fi >&2
trap result 0
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
	todo
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
if readlink mountpoint/symlink | tee /dev/stderr | md5sum - |
   grep -q '^52b6c9badcfa44b405995fb8e5f9fa31  -$'
then
	ok
else
	ko
fi
echo

run "Remove symlink"
if rm mountpoint/symlink &&
   ! test -L mountpoint/symlink
then
	ok
else
	ko
fi
echo
