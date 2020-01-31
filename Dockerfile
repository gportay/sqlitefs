FROM archlinux/base:latest

RUN pacman --noconfirm -Syu base-devel
RUN pacman --noconfirm -Syu git meson qt5-wayland rsync strace valgrind

ARG user
ARG uid
ARG groups
ARG home

RUN groupadd --non-unique --gid $groups $user
RUN useradd  --non-unique --gid $groups --uid $uid --create-home --home-dir $home --shell $SHELL $user
RUN echo "%$user ALL=(ALL) NOPASSWD: /usr/bin/pacman" >/etc/sudoers.d/$user

ENV EDITOR cat
USER $user
WORKDIR $home
RUN echo "source_safe /etc/makepkg.conf" >.makepkg.conf
RUN echo "OPTIONS+=(debug !strip)" >>.makepkg.conf

RUN mkdir -p $home/src/libc
WORKDIR $home/src/libc
RUN curl https://git.archlinux.org/svntogit/packages.git/plain/glibc/repos/core-x86_64/{PKGBUILD,bz20338.patch,file-truncated-while-reading-soname-after-patchelf.patch,glibc.install,lib32-glibc.conf,locale-gen,locale.gen.txt,sdt-config.h,sdt.h} -O -O -O -O -O -O -O -O -O -O
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN mkdir -p $home/src/fuse
WORKDIR $home/src/fuse
RUN curl https://git.archlinux.org/svntogit/packages.git/plain/fuse3/repos/extra-x86_64/PKGBUILD -O
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN mkdir -p $home/src/sqlite
WORKDIR $home/src/sqlite
RUN curl https://git.archlinux.org/svntogit/packages.git/plain/sqlite/repos/core-x86_64/{PKGBUILD,license.txt} -O -O
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN git clone https://aur.archlinux.org/auracle-git.git $home/src/auracle-git
WORKDIR $home/src/auracle-git
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN git clone https://aur.archlinux.org/pacaur-git.git $home/src/pacaur-git
WORKDIR $home/src/pacaur-git
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN pacaur --noconfirm -S perf hotspot
