FROM archlinux/base:latest

RUN pacman --noconfirm -Syu base-devel
RUN pacman --noconfirm -Syu meson strace valgrind

ARG user
ARG uid
ARG groups
ARG home

RUN groupadd --non-unique --gid $groups $user
RUN useradd  --non-unique --gid $groups --uid $uid --create-home --home-dir $home --shell $SHELL $user
RUN echo "%$user ALL=(ALL) NOPASSWD: /usr/bin/pacman" >/etc/sudoers.d/$user

USER $user
WORKDIR $home
RUN echo "source_safe /etc/makepkg.conf" >.makepkg.conf
RUN echo "OPTIONS+=(debug !strip)" >>.makepkg.conf

RUN mkdir -p $home/src/fuse
WORKDIR $home/src/fuse
RUN curl https://git.archlinux.org/svntogit/packages.git/plain/fuse3/repos/extra-x86_64/PKGBUILD -O
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN mkdir -p $home/src/sqlite
WORKDIR $home/src/sqlite
RUN curl https://git.archlinux.org/svntogit/packages.git/plain/sqlite/repos/core-x86_64/{PKGBUILD,license.txt} -O -O
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm
