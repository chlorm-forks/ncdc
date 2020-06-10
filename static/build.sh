#!/bin/sh

# This script assumes the following:
# - You have the following installed on your machine:
#   bash
#   make
#   GNU tar
#   wget
#   ncurses (with the 'tic' binary)
#   perl
#   python2
#   git
#   meson
#   ninja
#   (Anything else I forgot)
# - A checkout of the ncdc git repo can be found in "..", and the configure
#   script exists (i.e. autoreconf has been run).
# - You have musl-cross binaries available in MUSL_CROSS_PATH
#
# Usage:
#   ./build.sh $arch
#   Where $arch = 'arm', 'aarch64', 'i486' or 'x86_64'
#
# TODO:
# - Cross-compile to platforms other than Linux?
# - Automatically fetch & build musl-cross?


MUSL_CROSS_PATH=/opt/cross
ZLIB_VERSION=1.2.11
BZIP2_VERSION=1.0.8
SQLITE_VERSION=3320200
GMP_VERSION=6.2.0
NETTLE_VERSION=3.6
IDN_VERSION=2.3.0
GNUTLS_VERSION=3.6.14
NCURSES_VERSION=6.2
GLIB_VERSION=2.64.3
MAXMIND_VERSION=1.4.2


# We don't actually use pkg-config at all. Setting this variable to 'true'
# effectively tricks autoconf scripts into thinking that we have pkg-config
# installed, and that all packages it probes for exist. We handle the rest with
# manual CPPFLAGS/LDFLAGS.
export PKG_CONFIG=true 

export CFLAGS="-O3 -g -static"

export HOST_CC=gcc

# (The variables below are automatically set by the functions, they're defined
# here to make sure they have global scope and for documentation purposes.)

# This is the arch we're compiling for, e.g. arm.
TARGET=
# This is the name of the toolchain we're using, and thus the value we should
# pass to autoconf's --host argument.
HOST=
# Installation prefix.
PREFIX=
# Path of the extracted source code of the package we're currently building.
srcdir=

mkdir -p tarballs


# "Fetch, Extract, Move"
fem() { # base-url name targerdir extractdir 
  echo "====== Fetching and extracting $1 $2"
  cd tarballs
  if [ -n "$4" ]; then
    EDIR="$4"
  else
    EDIR=$(basename $(basename $(basename $2 .tar.bz2) .tar.gz) .tar.xz)
  fi
  if [ ! -e "$2" ]; then
    wget "$1$2" || exit
  fi
  if [ ! -d "$3" ]; then
    tar -xvf "$2" || exit
    mv "$EDIR" "$3"
  fi
  cd ..
}


prebuild() { # dirname
  if [ -e "$TARGET/$1/_built" ]; then
    echo "====== Skipping build for $TARGET/$1 (assumed to be done)"
    return 1
  fi
  echo "====== Starting build for $TARGET/$1"
  rm -rf "$TARGET/$1"
  mkdir -p "$TARGET/$1"
  cd "$TARGET/$1"
  srcdir="../../tarballs/$1"
  return 0
}


postbuild() {
  touch _built
  cd ../..
}


getzlib() {
  fem http://zlib.net/ zlib-$ZLIB_VERSION.tar.gz zlib
  prebuild zlib || return
  # zlib doesn't support out-of-source builds
  cp -R $srcdir/* .
  CC=$HOST-gcc ./configure --prefix=$PREFIX --static || exit
  make install || exit
  postbuild
}


getbzip2() {
  fem https://sourceware.org/pub/bzip2/ bzip2-$BZIP2_VERSION.tar.gz bzip2
  prebuild bzip2 || return
  cp -R $srcdir/* .
  make CC=$HOST-gcc AR=$HOST-ar RANLIB=$HOST-ranlib libbz2.a || exit
  mkdir -p $PREFIX/lib $PREFIX/include
  cp libbz2.a $PREFIX/lib
  cp bzlib.h $PREFIX/include
  postbuild
}


getsqlite() {
  fem http://sqlite.org/2020/ sqlite-autoconf-$SQLITE_VERSION.tar.gz sqlite
  prebuild sqlite || return
  $srcdir/configure --prefix=$PREFIX --disable-readline --disable-dynamic-extensions\
    --disable-fts4 --disable-fts5 --disable-json1 --disable-rtree\
    --disable-shared --enable-static --host=$HOST || exit
  make install-includeHEADERS install-libLTLIBRARIES || exit
  postbuild
}


getgmp() {
  fem ftp://ftp.gmplib.org/pub/gmp-$GMP_VERSION/ gmp-$GMP_VERSION.tar.xz gmp
  prebuild gmp || return
  $srcdir/configure --host=$HOST --disable-shared --without-readline --enable-static --prefix=$PREFIX || exit
  make install || exit
  postbuild
}


getnettle() {
  fem http://www.lysator.liu.se/~nisse/archive/ nettle-$NETTLE_VERSION.tar.gz nettle
  prebuild nettle || return
  $srcdir/configure --prefix=$PREFIX --enable-public-key --disable-shared --host=$HOST\
    CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib" || exit
  make install-headers install-static || exit
  postbuild
}


getidn() {
  fem http://ftp.gnu.org/gnu/libidn/ libidn2-$IDN_VERSION.tar.gz idn
  prebuild idn || return
  $srcdir/configure --prefix=$PREFIX --disable-nls --disable-valgrind-tests --disable-shared\
    --enable-static --host=$HOST CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib" || exit
  make install || exit
  postbuild
}


getgnutls() {
  fem ftp://ftp.gnutls.org/gcrypt/gnutls/v${GNUTLS_VERSION%.*}/ gnutls-$GNUTLS_VERSION.tar.xz gnutls
  prebuild gnutls || return
  $srcdir/configure --prefix=$PREFIX --disable-gtk-doc-html --disable-shared --disable-silent-rules\
    --enable-static --disable-cxx --disable-srp-authentication --disable-openssl-compatibility\
    --disable-guile --disable-tools --with-included-libtasn1 --without-p11-kit\
    --with-included-unistring --host=$HOST\
    CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib -Wl,--start-group -lnettle -lhogweed -lgmp -lidn2" || exit
  make || exit
  make -C gl install || exit
  make -C lib install || exit
  postbuild
}


getncurses() {
  fem http://ftp.gnu.org/pub/gnu/ncurses/ ncurses-$NCURSES_VERSION.tar.gz ncurses
  prebuild ncurses || return
  $srcdir/configure --prefix=$PREFIX\
    --without-cxx --without-cxx-binding --without-ada --without-manpages --without-progs\
    --without-tests --without-curses-h --without-pkg-config --without-shared --without-debug\
    --without-gpm --without-sysmouse --enable-widec --with-default-terminfo-dir=/usr/share/terminfo\
    --with-terminfo-dirs=/usr/share/terminfo:/lib/terminfo:/usr/local/share/terminfo\
    --with-fallbacks="screen linux vt100 xterm" --host=$HOST\
    CPPFLAGS=-D_GNU_SOURCE || exit
  make || exit
  make install.libs || exit
  postbuild
}


getglib() {
  fem http://ftp.gnome.org/pub/gnome/sources/glib/${GLIB_VERSION%.*}/ glib-$GLIB_VERSION.tar.xz glib
  prebuild glib || return

  # Get rid of GObject & GIO stuff from the meson build, ncdc doesn't need it.
  mv $srcdir/meson.build $srcdir/meson.build.orig
  grep -vE "subdir\('(gio|gobject|gmodule|fuzzing|tests)'\)" $srcdir/meson.build.orig\
      | grep -vE '^(gobject|gmodule|gio)inc = '\
      | sed -E "s/.+GLIB_LOCALE_DIR.+/glib_conf.set_quoted('GLIB_LOCALE_DIR', '\\/usr\\/share\\/locale')/"\
      > $srcdir/meson.build

  meson setup . $srcdir --cross-file ../../meson-cross-$TARGET.txt --prefix=$PREFIX\
      --localedir=localexxx -Ddefault_library=static\
      -Dlibmount=disabled -Dinternal_pcre=true -Dnls=disabled -Dc_args="$CFLAGS" -Dcpp_args="$CFLAGS" || exit
  ninja install || exit
  postbuild
}


getmaxmind() {
  fem https://github.com/maxmind/libmaxminddb/releases/download/${MAXMIND_VERSION}/ libmaxminddb-${MAXMIND_VERSION}.tar.gz maxmind
  prebuild maxmind || return
  cp -Rp $srcdir/* .
  ./configure --prefix=$PREFIX --host=$HOST --disable-shared || exit
  make install || exit
  postbuild
}


getncdc() {
  prebuild ncdc || return
  srcdir=../../..
  $srcdir/configure --host=$HOST --disable-silent-rules --with-geoip\
    CPPFLAGS="-I$PREFIX/include -D_GNU_SOURCE -Wno-deprecated-declarations" LDFLAGS="-static -L$PREFIX/lib -L$PREFIX/lib64 -lz -lbz2"\
    SQLITE_LIBS=-lsqlite3 GEOIP_LIBS=-lmaxminddb GNUTLS_LIBS="-lgnutls -lz -lhogweed -lnettle -lgmp -lidn2"\
    NCURSES_CFLAGS="-I$PREFIX/include/ncursesw" NCURSES_LIBS="-lncursesw"\
    GLIB_LIBS="-pthread -lglib-2.0 -lgthread-2.0" GLIB_CFLAGS="-I$PREFIX/include/glib-2.0 -I$PREFIX/lib/glib-2.0/include" || exit
  # Make sure that the Makefile dependencies for makeheaders and gendoc are "up-to-date"
  mkdir -p deps deps/.deps doc doc/.deps
  touch deps/.dirstamp deps/.deps/.dirstamp deps/makeheaders.o doc/.dirstamp doc/.deps/.dirstamp doc/gendoc.o 
  gcc $srcdir/deps/makeheaders.c -o makeheaders || exit
  gcc -I. -I$srcdir $srcdir/doc/gendoc.c -o gendoc || exit
  make || exit

  VER=`cd '../../..' && git describe --abbrev=5 --dirty= | sed s/^v//`
  tar -czf ../../ncdc-linux-$TARGET-$VER-unstripped.tar.gz ncdc
  $HOST-strip ncdc
  tar -czf ../../ncdc-linux-$TARGET-$VER.tar.gz ncdc
  echo "====== ncdc-linux-$TARGET-$VER.tar.gz and -unstripped created."

  postbuild
}


allncdc() {
  getzlib
  getbzip2
  getsqlite
  getgmp
  getnettle
  getidn
  getgnutls
  getncurses
  getglib
  getmaxmind
  getncdc
}


buildarch() {
  TARGET=$1
  case $TARGET in
    arm)     HOST=arm-linux-musleabi ;;
    aarch64) HOST=aarch64-linux-musl ;;
    i486)    HOST=i486-linux-musl    ;;
    x86_64)  HOST=x86_64-linux-musl  ;;
    *)       echo "Unknown target: $TARGET"; exit ;;
  esac
  PREFIX="`pwd`/$TARGET/inst"
  mkdir -p $TARGET $PREFIX
  ln -s lib $PREFIX/lib64

  OLDPATH="$PATH"
  PATH="$PATH:$MUSL_CROSS_PATH/$HOST/bin"
  allncdc
  PATH="$OLDPATH"
}

[ -z "$@" ] && set -- arm aarch64 i486 x86_64
for a in "$@"; do
  buildarch $a
done
