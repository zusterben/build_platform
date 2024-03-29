#!/bin/bash

set -e
set -x

#ARCH=arm64
#ARCH=arm
ARCH=mips
#ARCH=mipsle
PWD=`pwd`
#prefix asuswrt:/jffs/softcenter,openwrt:/usr
if [ "$ARCH" = "arm" ];then
#armv7l
export CFLAGS="-I $PWD/opt/cross/arm-linux-musleabi/arm-linux-musleabi/include -Os"
export CXXFLAGS="-I $PWD/opt/cross/arm-linux-musleabi/arm-linux-musleabi/include"
export CC=$PWD/opt/cross/arm-linux-musleabi/bin/arm-linux-musleabi-gcc
export CXX=$PWD/opt/cross/arm-linux-musleabi/bin/arm-linux-musleabi-g++
export CORSS_PREFIX=$PWD/opt/cross/arm-linux-musleabi/bin/arm-linux-musleabi-
export TARGET_CFLAGS=""
export BOOST_ABI=sysv
elif [ "$ARCH" = "arm64" ];then
export CFLAGS="-I $PWD/opt/cross/aarch64-linux-musl/aarch64-linux-musl/include -Os"
export CXXFLAGS="-I $PWD/opt/cross/aarch64-linux-musl/aarch64-linux-musl/include"
export CC=$PWD/opt/cross/aarch64-linux-musl/bin/aarch64-linux-musl-gcc
export CXX=$PWD/opt/cross/aarch64-linux-musl/bin/aarch64-linux-musl-g++
export CORSS_PREFIX=$PWD/opt/cross/aarch64-linux-musl/bin/aarch64-linux-musl-
export TARGET_CFLAGS=""
export BOOST_ABI=aapcs
elif [ "$ARCH" = "mips" ];then
#mips
export CFLAGS="-I $PWD/opt/cross/mips-linux-musl/mips-linux-musl/include -Os"
export CXXFLAGS="-I $PWD/opt/cross/mips-linux-musl/mips-linux-musl/include"
export CC=$PWD/opt/cross/mips-linux-musl/bin/mips-linux-musl-gcc
export CXX=$PWD/opt/cross/mips-linux-musl/bin/mips-linux-musl-g++
export CORSS_PREFIX=$PWD/opt/cross/mips-linux-musl/bin/mips-linux-musl-
export TARGET_CFLAGS=" -DBOOST_NO_FENV_H"
export BOOST_ABI=o32
export mipsarch=" architecture=mips32r2"
elif [ "$ARCH" = "mipsle" ];then
export CFLAGS="-I $PWD/opt/cross/mipsel-linux-musl/mipsel-linux-musl/include -Os"
export CXXFLAGS="-I $PWD/opt/cross/mipsel-linux-musl/mipsel-linux-musl/include"
export CC=$PWD/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-gcc
export CXX=$PWD/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-g++
export CORSS_PREFIX=$PWD/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-
export TARGET_CFLAGS=" -DBOOST_NO_FENV_H"
export BOOST_ABI=o32
export mipsarch=" architecture=mips32r2"
fi

BASE=`pwd`
SRC=$BASE/src
WGET="wget --prefer-family=IPv4"
DEST=$BASE/opt
LDFLAGS="-L$DEST/lib -Wl,--gc-sections"
CPPFLAGS="-I$DEST/include"
CXXFLAGS="$CXXFLAGS $CFLAGS"
if [ "$ARCH" = "arm" ];then
CONFIGURE="linux-armv4 -Os -static --prefix=/opt zlib enable-ssl3 enable-ssl3-method enable-tls1_3 --with-zlib-lib=$DEST/lib --with-zlib-include=$DEST/include -DOPENSSL_PREFER_CHACHA_OVER_GCM enable-weak-ssl-ciphers"
ARCHBUILD=arm
elif [ "$ARCH" = "arm64" ];then
CONFIGURE="linux-aarch64 -Os -static --prefix=/opt zlib enable-ssl3 enable-ssl3-method enable-tls1_3 --with-zlib-lib=$DEST/lib --with-zlib-include=$DEST/include -DOPENSSL_PREFER_CHACHA_OVER_GCM enable-weak-ssl-ciphers"
ARCHBUILD=aarch64
elif [ "$ARCH" = "mips" ];then
CONFIGURE="linux-mips32 -Os -static --prefix=/opt zlib enable-ssl3 enable-ssl3-method enable-tls1_3 --with-zlib-lib=$DEST/lib --with-zlib-include=$DEST/include -DOPENSSL_PREFER_CHACHA_OVER_GCM enable-weak-ssl-ciphers"
ARCHBUILD=mips
elif [ "$ARCH" = "mipsle" ];then
CONFIGURE="linux-mips32 -Os -static --prefix=/opt zlib enable-ssl3 enable-ssl3-method enable-tls1_3 --with-zlib-lib=$DEST/lib --with-zlib-include=$DEST/include -DOPENSSL_PREFER_CHACHA_OVER_GCM enable-weak-ssl-ciphers"
ARCHBUILD=mipsle
fi
MAKE="make"

######## ####################################################################
# ZLIB # ####################################################################
######## ####################################################################

[ ! -d "zlib-1.2.11" ] && tar xvJf zlib-1.2.11.tar.xz
cd zlib-1.2.11
if [ ! -f "stamp-h1" ];then
CC=${CORSS_PREFIX}gcc \
LDFLAGS=$LDFLAGS \
CPPFLAGS=$CPPFLAGS \
CFLAGS=$CFLAGS \
CXXFLAGS=$CXXFLAGS \
CROSS_PREFIX=${CORSS_PREFIX} \
./configure \
--prefix=/opt \
--static

$MAKE
make install DESTDIR=$BASE
touch stamp-h1
fi

########### #################################################################
# OPENSSL # #################################################################
########### #################################################################

cd $BASE
[ ! -d "openssl-1.1.1d" ] && tar zxvf openssl-1.1.1d.tar.gz
cd $BASE/openssl-1.1.1d
if [ ! -f "stamp-h1" ];then
    if [ ! -e patched ]
    then
        for f in "../patches/"*.patch ; do
            patch -p1 < "$f"
        done
        touch patched
    fi
./Configure $CONFIGURE

make 
make install INSTALLTOP=$DEST OPENSSLDIR=$DEST/ssl
touch stamp-h1
fi

########### #################################################################
#  BOOST  # #################################################################
########### #################################################################

cd $BASE
[ ! -d "boost_1_71_0" ] && tar jxvf boost_1_71_0.tar.bz2
cd $BASE/boost_1_71_0
if [ ! -f "stamp-h1" ];then
rm -rf bin.v2
rm -rf project-config.jam
rm -rf tools/build/src/user-config.jam
cd tools/build/src/engine
CC=/usr/bin/gcc \
CXX=/usr/bin/g++ \
CFLAGS="" \
CPPFLAGS="" \
CXXFLAGS="$CFLAGS" \
./build.sh gcc
cd $BASE/boost_1_71_0
cp -rf tools/build/src/engine/b2 ./b2
echo "using gcc : : ${CORSS_PREFIX}gcc : <compileflags>\"${TARGET_CFLAGS}\" <cxxflags>\" -std=gnu++14\" <linkflags>\" -pthread -lrt\" ;" > tools/build/src/user-config.jam
#./bootstrap.sh 
#sed -i 's/using gcc/using gcc: :${CORSS_PREFIX}gcc ;/g' project-config.jam
#cp -rf ../gcc.jam $BASE/boost_1_71_0/tools/build/src/tools/gcc.jam
CC=${CORSS_PREFIX}gcc \
CXX=${CORSS_PREFIX}g++ \
./b2 install --ignore-site-config --toolset=gcc --prefix=$DEST abi=$BOOST_ABI --no-cmake-config --layout=tagged --build-type=minimal link=static threading=multi runtime-link=static $mipsarch variant=release --disable-long-double -sNO_BZIP2=1 -sZLIB_INCLUDE=$DEST/include -sZLIB_LIBPATH=$DEST/lib --with-system --with-program_options --with-date_time
#--without-mpi --without-python --without-graph_parallel --without-test --without-serialization
mv $DEST/lib/libboost_date_time-*.a $DEST/lib/libboost_date_time.a 
mv $DEST/lib/libboost_program_options-*.a $DEST/lib/libboost_program_options.a 
mv $DEST/lib/libboost_system-*.a $DEST/lib/libboost_system.a 
touch stamp-h1
fi

########### #################################################################
#  CMAKE  # #################################################################
########### #################################################################

cd $BASE
[ ! -d "cmake-3.13.2" ] && tar zxvf cmake-3.13.2.tar.gz
cd $BASE/cmake-3.13.2
if [ ! -f "stamp-h1" ];then
CC=/usr/bin/gcc \
CXX=/usr/bin/g++ \
CFLAGS="-I /usr/include" \
CPPFLAGS="-I /usr/include" \
CXXFLAGS="$CFLAGS" \
./bootstrap --prefix=$DEST/bin/cmake
make
make install
touch stamp-h1
fi

########### #################################################################
# LIBEVENT# #################################################################
########### #################################################################
cd $BASE
[ ! -d "libevent-2.1.11-stable" ] && tar zxvf libevent-2.1.11-stable.tar.gz
cd $BASE/libevent-2.1.11-stable
if [ ! -f "stamp-h1" ];then
./configure --disable-debug-mode --disable-samples --disable-libevent-regress --prefix=/opt --host=$ARCHBUILD-linux && make
#cp -rf .libs/libevent*.a $DEST/lib
make install DESTDIR=$BASE
touch stamp-h1
fi
########### #################################################################
###LIBEV### #################################################################
########### #################################################################
cd $BASE
[ ! -d "libev-4.22" ] && tar zxvf libev-4.22.tar.gz
cd $BASE/libev-4.22
if [ ! -f "stamp-h1" ];then
./configure --enable-static --disable-shared --prefix=/opt --host=$ARCHBUILD-linux && make
#cp -rf .libs/libevent*.a $DEST/lib
make install DESTDIR=$BASE
touch stamp-h1
fi
########### #################################################################
###pcre#### #################################################################
########### #################################################################
cd $BASE
[ ! -d "pcre-8.41" ] && tar jxvf pcre-8.41.tar.bz2
cd $BASE/pcre-8.41
if [ ! -f "stamp-h1" ];then
./configure --disable-shared --enable-utf8 --enable-unicode-properties --enable-pcre16 --with-match-limit-recursion=16000 --disable-cpp --prefix=/opt --host=$ARCHBUILD-linux && make
#cp -rf .libs/libevent*.a $DEST/lib
make install DESTDIR=$BASE
touch stamp-h1
fi
########### #################################################################
##mbedtls## #################################################################
########### #################################################################
cd $BASE
[ ! -d "mbedtls-2.16.3" ] && tar zxvf mbedtls-2.16.3.tgz
cd $BASE/mbedtls-2.16.3
if [ ! -f "stamp-h1" ];then
CC=${CORSS_PREFIX}gcc \
LDFLAGS=$LDFLAGS" -static" \
CPPFLAGS=$CPPFLAGS \
CFLAGS=$CFLAGS \
CXXFLAGS=$CXXFLAGS \
CROSS_PREFIX=${CORSS_PREFIX} \
make install DESTDIR=$DEST
touch stamp-h1
fi
########### #################################################################
##c-ares### #################################################################
########### #################################################################
cd $BASE
[ ! -d "c-ares-1.14.0" ] && tar zxvf c-ares-1.14.0.tar.gz
cd $BASE/c-ares-1.14.0
if [ ! -f "stamp-h1" ];then
./buildconf
CC=${CORSS_PREFIX}gcc \
LDFLAGS=$LDFLAGS" -static" \
CPPFLAGS=$CPPFLAGS \
CFLAGS="-g0 -O2 -Wno-system-headers " \
CXXFLAGS=$CXXFLAGS \
CROSS_PREFIX=${CORSS_PREFIX} \
./configure --prefix=/opt --host=$ARCHBUILD-linux --enable-shared=no --enable-static=yes
make install DESTDIR=$BASE
touch stamp-h1
fi
########### #################################################################
#libsodium# #################################################################
########### #################################################################
cd $BASE
[ ! -d "libsodium-1.0.16" ] && tar zxvf libsodium-1.0.16.tar.gz
cd $BASE/libsodium-1.0.16
if [ ! -f "stamp-h1" ];then
./configure --disable-shared --disable-ssp --prefix=/opt --host=$ARCHBUILD-linux && make
#cp -rf .libs/libevent*.a $DEST/lib
make install DESTDIR=$BASE
touch stamp-h1
fi
########### #################################################################
#  PDNSD  # #################################################################
########### #################################################################
cd $BASE
[ ! -d "pdnsd-1.2.9b-par" ] && tar zxvf pdnsd-1.2.9b-par.tar.gz
cd $BASE/pdnsd-1.2.9b-par
CC=${CORSS_PREFIX}gcc \
LDFLAGS=$LDFLAGS" -static" \
CPPFLAGS=$CPPFLAGS \
CFLAGS=$CFLAGS \
CXXFLAGS=$CXXFLAGS \
CROSS_PREFIX=${CORSS_PREFIX} \
./configure --with-cachedir=/var/pdnsd --with-target=Linux --host=$ARCHBUILD-linux --with-debug=1
make
${CORSS_PREFIX}strip src/pdnsd
cd $BASE
mkdir -p bin/$ARCH
cp -rf $BASE/pdnsd-1.2.9b-par/src/pdnsd bin/$ARCH/pdnsd
########### #################################################################
#redsocks2# #################################################################
########### #################################################################

cd $BASE
[ ! -d "redsocks2-0.67" ] && tar zxvf redsocks2-0.67.tar.gz
cd $BASE/redsocks2-0.67
ENABLE_STATIC=y \
DISABLE_SHADOWSOCKS=y \
CC=${CORSS_PREFIX}gcc \
LDFLAGS=$LDFLAGS" -static" \
CPPFLAGS=$CPPFLAGS \
CFLAGS=$CFLAGS \
CXXFLAGS=$CXXFLAGS \
CROSS_PREFIX=${CORSS_PREFIX} \
make
#make
${CORSS_PREFIX}strip redsocks2
cd $BASE
mkdir -p bin/$ARCH
cp -rf $BASE/redsocks2-0.67/redsocks2 bin/$ARCH
########### #################################################################
#microsocks# ################################################################
########### #################################################################
cd $BASE
[ ! -d "microsocks" ] && tar zxvf microsocks.1.0.1.tar.gz
cd $BASE/microsocks
CC=${CORSS_PREFIX}gcc \
LDFLAGS=$LDFLAGS" -static" \
make
${CORSS_PREFIX}strip microsocks
cd $BASE
mkdir -p bin/$ARCH
cp -rf $BASE/microsocks/microsocks bin/$ARCH
########### #################################################################
#chinadnsng# ################################################################
########### #################################################################
cd $BASE
[ ! -d "chinadns-ng" ] && tar zxvf chinadns-ng.tar.gz
cd $BASE/chinadns-ng
make CC=${CORSS_PREFIX}gcc
${CORSS_PREFIX}strip chinadns-ng
cd $BASE
mkdir -p bin/$ARCH
cp -rf $BASE/chinadns-ng/chinadns-ng bin/$ARCH
########### #################################################################
#dns2socks# #################################################################
########### #################################################################
cd $BASE
[ ! -d "dns2socks" ] && unzip dns2socks.zip -d dns2socks
cd $BASE/dns2socks
${CC} ${CFLAGS} ${LDFLAGS} -static DNS2SOCKS/DNS2SOCKS.c -o dns2socks
${CORSS_PREFIX}strip dns2socks
cd $BASE
mkdir -p bin/$ARCH
cp -rf $BASE/dns2socks/dns2socks bin/$ARCH
########### #################################################################
#ipt2socks# #################################################################
########### #################################################################
cd $BASE
[ ! -d "ipt2socks-1.1.3" ] && tar zxvf ipt2socks-1.1.3.tar.gz
cd $BASE/ipt2socks-1.1.3
make CC=${CORSS_PREFIX}gcc LDFLAGS=$LDFLAGS" -static"
${CORSS_PREFIX}strip ipt2socks
cd $BASE
mkdir -p bin/$ARCH
cp -rf $BASE/ipt2socks-1.1.3/ipt2socks bin/$ARCH
########### #################################################################
####lua#### #################################################################
########### #################################################################
cd $BASE
[ ! -d "lua-cjson" ] && tar zxvf lua-cjson.tar.gz
cd $BASE/lua-cjson
make CC=${CORSS_PREFIX}gcc AR="${CORSS_PREFIX}ar rcu" RANLIB="${CORSS_PREFIX}ranlib" INSTALL_ROOT=/opt CFLAGS="$CPPFLAGS $CFLAGS -fPIC -std=gnu99" PKG_VERSION=-"5.1.5" MYLDFLAGS="$LDFLAGS"
${CORSS_PREFIX}strip cjson.so
cd $BASE
mkdir -p bin/$ARCH
mkdir -p bin/$ARCH/cjson
cp -rf $BASE/lua-cjson/cjson.so bin/$ARCH
cp -rf $BASE/lua-cjson/cjson/util.lua bin/$ARCH/cjson
########### #################################################################
#lua-cjson# #################################################################
########### #################################################################
cd $BASE
[ ! -d "lua-5.1.5" ] && tar zxvf lua-5.1.5.tar.gz
cd $BASE/lua-5.1.5
make CC=${CORSS_PREFIX}gcc AR="${CORSS_PREFIX}ar rcu" RANLIB="${CORSS_PREFIX}ranlib" INSTALL_ROOT=/opt CFLAGS="$CPPFLAGS $CFLAGS -DLUA_USE_LINUX -fPIC -std=gnu99 -static" PKG_VERSION=-"5.1.5" MYLDFLAGS="$LDFLAGS -static" linux
${CORSS_PREFIX}strip src/lua
cd $BASE
mkdir -p bin/$ARCH
cp -rf $BASE/lua-5.1.5/src/lua bin/$ARCH
########### #################################################################
##httping## #################################################################
########### #################################################################
cd $BASE
[ ! -d "httping-2.5" ] && tar zxvf httping-2.5.tar.gz
cd $BASE/httping-2.5
CFLAGS="-I$DEST/include -DENABLE_HELP -static $CFLAGS" LDFLAGS="-L$DEST/lib -Wl,--gc-sections" \
make 
${CORSS_PREFIX}strip httping
cd $BASE
mkdir -p bin/$ARCH
cp $BASE/httping-2.5/httping bin/$ARCH

########### #################################################################
####jq##### #################################################################
########### #################################################################
cd $BASE
[ ! -d "jq" ] && tar zxvf jq.tar.gz
cd $BASE/jq
autoreconf -ivf
./configure --disable-maintainer-mode --enable-all-static --prefix=/opt --host=$ARCHBUILD-linux
make 
${CORSS_PREFIX}strip jq
cd $BASE
mkdir -p bin/$ARCH
cp $BASE/jq/jq bin/$ARCH


########### #################################################################
#simple-obfs ################################################################
########### #################################################################
cd $BASE
[ ! -d "simple-obfs" ] && tar zxvf simple-obfs.tar.gz
cd $BASE/simple-obfs
./autogen.sh
LIBS="-lpthread -lm" \
LDFLAGS="-Wl,-static -static -static-libgcc -L$DEST/lib" \
CFLAGS="-I$DEST/include" \
./configure --disable-ssp --disable-assert --disable-documentation --prefix=/opt --host=$ARCHBUILD-linux
make 
${CORSS_PREFIX}strip src/obfs-server
${CORSS_PREFIX}strip src/obfs-local
cd $BASE
mkdir -p bin/$ARCH
cp $BASE/simple-obfs/src/obfs-server bin/$ARCH
cp $BASE/simple-obfs/src/obfs-local bin/$ARCH
########### #################################################################
## ssr  ### #################################################################
########### #################################################################
cd $BASE
[ ! -d "shadowsocksr-libev-2.5.3" ] && tar zxvf shadowsocksr-libev-2.5.3.tar.gz
cd $BASE/shadowsocksr-libev-2.5.3
if [ ! -e patched ]
then
	for f in "../sspatches/"*.patch ; do
		patch -p1 < "$f"
	done
	touch patched
fi
./autogen.sh
CC=${CORSS_PREFIX}gcc \
CPPFLAGS=$CPPFLAGS \
CFLAGS=$CFLAGS \
CXXFLAGS=$CXXFLAGS \
CROSS_PREFIX=${CORSS_PREFIX} \
LIBS="-lpthread" LDFLAGS="-Wl,-static -static -static-libgcc -lgcc -L$DEST/lib" CFLAGS="-I$DEST/include" \
ac_cv_prog_PCRE_CONFIG="$DEST/bin/pcre-config" \
./configure --prefix=/opt --disable-documentation --disable-ssp --disable-assert \
	--with-crypto-library=openssl --host=$ARCHBUILD-linux
make
${CORSS_PREFIX}strip src/ss-local
${CORSS_PREFIX}strip server/ss-server
${CORSS_PREFIX}strip server/ss-check
${CORSS_PREFIX}strip src/ss-redir
cd $BASE
mkdir -p bin/$ARCH
mv $BASE/shadowsocksr-libev-2.5.3/server/ss-server bin/$ARCH/ssr-server
mv $BASE/shadowsocksr-libev-2.5.3/src/ss-local bin/$ARCH/ssr-local
mv $BASE/shadowsocksr-libev-2.5.3/server/ss-check bin/$ARCH/ssr-check
mv $BASE/shadowsocksr-libev-2.5.3/src/ss-redir bin/$ARCH/ssr-redir
########### #################################################################
### ss  ### #################################################################
########### #################################################################
cd $BASE
[ ! -d "shadowsocks-libev-3.3.4" ] && tar zxvf shadowsocks-libev-3.3.4.tar.gz
cd $BASE/shadowsocks-libev-3.3.4
LIBS="-lpthread" LDFLAGS="-Wl,-static -static -static-libgcc -L$DEST/lib" CFLAGS="-I$DEST/include" \
ac_cv_prog_PCRE_CONFIG="$DEST/bin/pcre-config" \
./configure --prefix=/opt --disable-documentation --disable-ssp --disable-assert \
	 --host=$ARCHBUILD-linux --with-mbedtls=$DEST --with-pcre=$DEST --with-sodium=$DEST
make
${CORSS_PREFIX}strip src/ss-local
${CORSS_PREFIX}strip src/ss-server
${CORSS_PREFIX}strip src/ss-redir
cd $BASE
mkdir -p bin/$ARCH
mv $BASE/shadowsocks-libev-3.3.4/src/ss-server bin/$ARCH/ss-server
mv $BASE/shadowsocks-libev-3.3.4/src/ss-local bin/$ARCH/ss-local
mv $BASE/shadowsocks-libev-3.3.4/src/ss-redir bin/$ARCH/ss-redir
########### #################################################################
# TROJAN  # #################################################################
########### #################################################################

cd $BASE
[ ! -d "trojan-1.16.0" ] && tar zxvf trojan-1.16.0.tar.gz
cd $BASE/trojan-1.16.0
rm -rf CMakeFiles
rm -rf CMakeCache.txt

cp -rf ../CMakeLists.txt ./CMakeLists.txt
sed -i '/Build Flags/d' src/main.cpp
export CMAKE_ROOT=$DEST/bin/cmake
CC=${CORSS_PREFIX}gcc \
CXX=${CORSS_PREFIX}g++ \
LDFLAGS=$LDFLAGS" -static" \
CPPFLAGS=$CPPFLAGS \
CFLAGS=$CFLAGS \
CXXFLAGS=$CXXFLAGS \
$DEST/bin/cmake/bin/cmake -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_VERSION=1 -DCMAKE_SYSTEM_PROCESSOR=$ARCH -DCMAKE_BUILD_TYPE=Release -DCMAKE_SOURCE_DIR=$DEST/bin/cmake -DBoost_DEBUG=ON -DBoost_NO_BOOST_CMAKE=ON -DLINK_DIRECTORIES=$DEST/lib -DCMAKE_FIND_ROOT_PATH=$DEST -DBOOST_ROOT=$DEST -DBoost_INCLUDE_DIR=$DEST/include -DBoost_LIBRARY_DIRS=$DEST/lib -DBOOST_LIBRARYDIR=$DEST/lib -DOPENSSL_CRYPTO_LIBRARY=$DEST/lib -DOPENSSL_INCLUDE_DIR=$DEST/include -DOPENSSL_SSL_LIBRARY=$DEST/lib -DBoost_USE_STATIC_LIBS=TRUE -DBoost_PROGRAM_OPTIONS_LIBRARY_RELEASE=$DEST/lib -DBoost_SYSTEM_LIBRARY_RELEASE=$DEST/lib -DCMAKE_SKIP_RPATH=NO -DDEFAULT_CONFIG=/jffs/softcenter/etc/trojan.json -DCMAKE_FIND_LIBRARY_SUFFIXES=.a \
-DENABLE_MYSQL=OFF -DENABLE_NAT=ON -DENABLE_REUSE_PORT=ON -DENABLE_SSL_KEYLOG=ON -DENABLE_TLS13_CIPHERSUITES=ON -DFORCE_TCP_FASTOPEN=OFF -DSYSTEMD_SERVICE=OFF -DOPENSSL_USE_STATIC_LIBS=TRUE
make
${CORSS_PREFIX}strip trojan
cd $BASE
mkdir -p bin/$ARCH
cp -rf $BASE/trojan-1.16.0/trojan bin/$ARCH
