#!/bin/bash
source /opt/LTBOXCL02-linuxAPP/environment-setup-armv7a-vfp-neon-oe-linux-gnueabi
cur=$(cd `dirname $0`; pwd)
echo "install path:$cur"
if [ '$1' == 'clear' ] 
then
	make clear
else
	./configure --prefix=$cur/../ --host=armv-linux
	#./configure --prefix=/cache/tools --host=armv7-linux
	make & make install
fi
exit
