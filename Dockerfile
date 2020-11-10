FROM archlinux/base:latest

RUN pacman --noconfirm -Syu base-devel
RUN pacman --noconfirm -Syu git meson noto-fonts qt5-wayland rsync strace valgrind

ARG user
ARG uid
ARG groups
ARG home

RUN groupadd --non-unique --gid $groups $user
RUN useradd  --non-unique --gid $groups --uid $uid --create-home --home-dir $home --shell $SHELL $user
RUN echo "%$user ALL=(ALL) NOPASSWD: /usr/bin/pacman" >/etc/sudoers.d/$user

RUN pacman --noconfirm -Syu asp

ENV EDITOR cat
USER $user
WORKDIR $home
RUN echo "source_safe /etc/makepkg.conf" >.makepkg.conf
RUN echo "OPTIONS+=(debug !strip)" >>.makepkg.conf

RUN mkdir -p $home/src/

WORKDIR $home/src/
RUN asp checkout glibc
WORKDIR $home/src/glibc/repos/core-x86_64/
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

WORKDIR $home/src/
RUN asp checkout fuse3
WORKDIR $home/src/fuse3/repos/extra-x86_64/
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

WORKDIR $home/src/
RUN asp checkout sqlite
WORKDIR $home/src/sqlite/repos/core-x86_64/
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN git clone https://aur.archlinux.org/auracle-git.git $home/src/auracle-git
WORKDIR $home/src/auracle-git
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN git clone https://aur.archlinux.org/pacaur-git.git $home/src/pacaur-git
WORKDIR $home/src/pacaur-git
RUN makepkg --skippgpcheck --syncdeps --install --noconfirm

RUN pacaur --noconfirm -Sy perf hotspot
