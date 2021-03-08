#!/bin/bash
#source /opt/fsl-imx-x11/4.1.15-2.1.0/environment-setup-cortexa9hf-neon-poky-linux-gnueabi
#source /opt/fsl-imx-fb/4.14-sumo/environment-setup-cortexa9hf-neon-poky-linux-gnueabi

basepath=$(cd `dirname $0`; pwd)
if [ ! -d $basepath/Bin/build ]
then
	echo "make build dir"
	mkdir $basepath/Bin/build -p
fi

cd $basepath/Bin/build
if [ "$1" == "rebuild" ]
then
	echo "**********rebuild makefile"
	rm -rf ./*
fi
cmake -DPLATFORM=Linux_ARM  ../../
#make -j8
make
