#!/bin/bash
#
# Copyright (C) 2019-2020 Gaël PORTAY
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
	cat <<EOF >mountpoint/autorun.inf
[autorun]
label=sqlitefs
EOF

	mkdir -p mountpoint/.Trash
else
	sqlitefs -o nonempty -d mountpoint/ &
	while ! mountpoint --quiet mountpoint
	do
		sleep 0.1
	done
fi

run "List directory content"
if ls -1 mountpoint | tee /dev/stderr | \
   grep autorun.inf
then
	ok
else
	ko
fi
echo

run "Test file existance"
if test -e mountpoint/autorun.inf | tee /dev/stderr
then
	ok
else
	ko
fi
echo

run "Concatenate file"
if cat mountpoint/autorun.inf | tee /dev/stderr | md5sum |
   grep -q '^ef86bb7c399ba701ef65c96a21f383da  -$'
then
	ok
else
	ko
fi
echo

run "Touch file"
if touch mountpoint/touched &&
   test -e mountpoint/touched
then
	ok
else
	ko
fi
echo

run "Change ownership"
if fakeroot -- /bin/sh -c '
   chown root:root mountpoint/touched &&
   stat --printf="%U:%G\n" mountpoint/touched | tee /dev/stderr |
   grep -q "^root:root\$"
   '
then
	ok
else
	ko
fi
echo

run "Change mode"
if chmod 664 mountpoint/touched &&
   stat --printf="%a\n" mountpoint/touched | tee /dev/stderr |
   grep -q '^664$'
then
	ok
else
	ko
fi
echo

run "Echo in file"
if echo "Hello, World" >mountpoint/touched &&
   cat mountpoint/touched | tee /dev/stderr | md5sum |
   grep -q '^9af2f8218b150c351ad802c6f3d66abe  -$'
then
	ok
else
	ko
fi
echo

run "Move file"
if mv mountpoint/touched mountpoint/echoed &&
   ! test -e mountpoint/touched &&
   test -e mountpoint/echoed
then
	ok
else
	ko
fi
echo

run "Remove file"
if rm mountpoint/echoed &&
   ! test -e mountpoint/echoed
then
	ok
else
	todo
fi
echo

run "Copy file"
if cp README.md mountpoint/ &&
   test -e mountpoint/README.md
then
	ok
else
	ko
fi
echo

run "Remove file"
if rm mountpoint/README.md &&
   ! test -e mountpoint/README.md
then
	ok
else
	todo
fi
echo

run "Make directory"
if mkdir -p mountpoint/dir &&
   test -d mountpoint/dir
then
	ok
else
	todo
fi
echo

run "Remove directory"
if rmdir mountpoint/dir &&
   ! test -d mountpoint/dir
then
	ok
else
	todo
fi
echo

run "Make symbolic link"
if ln -sf .Trash mountpoint/symlink &&
   test -L mountpoint/symlink
then
	ok
else
	todo
fi
echo

run "Read symbolic link"
if readlink mountpoint/symlink | tee /dev/stderr | md5sum - |
   grep -q '^52b6c9badcfa44b405995fb8e5f9fa31  -$'
then
	ok
else
	todo
fi
echo

run "Remove symlink"
if rm mountpoint/symlink &&
   ! test -L mountpoint/symlink
then
	ok
else
	todo
fi
echo
