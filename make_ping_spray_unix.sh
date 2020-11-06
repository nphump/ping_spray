#!/bin/bash

# debug="-g -O0" # debug
debug="-O2" # release

exec 2>&1

ARCH=`uname -p`

if [ ! -f "endian.h" ]; then
	if [ $ARCH == "sparc" ]; then
		echo "#define BIGENDIAN 1" > endian.h
	else
		echo "#define LITTLEENDIAN 1" > endian.h
	fi
fi

echo $ARCH | grep 86 > /dev/null
if [ $? -eq 0 ]; then
	ARCH="x86"
fi
PLATFORM="${ARCH}-64-`uname -s`"

if [ $(uname) == "SunOS" ]; then
        compiler="/usr/sfw/bin/g++"
		compile_opts="-m64"
		link_opts="-m64 -pthreads -lsocket -lnsl"
else
        compiler="/usr/bin/g++"
		compile_opts="-m64"
		#link_opts="-m64 -pthread -ldl -lnsl"
		link_opts="-m64 -pthread -ldl"
fi

$compiler $debug $compile_opts -Wall -c ping_spray_unix.cpp
$compiler $debug $link_opts ping_spray_unix.o $libs -o ping_spray

