#!/bin/bash
#source /opt/fsl-imx-x11/4.1.15-2.1.0/environment-setup-cortexa9hf-neon-poky-linux-gnueabi
source /opt/fsl-imx-fb/4.14-sumo/environment-setup-cortexa9hf-neon-poky-linux-gnueabi
if [ ! -d build ]
then
	echo "make build dir"
	mkdir build
fi

cd build
if [ "$1" == "rebuild" ]
then
	echo "**********rebuild makefile"
	rm -rf ./*
fi
echo "PATH:$PATH"
cmake -DPLATFORM=Linux_arm  ../
make -j8

