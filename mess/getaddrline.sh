#!/bin/bash
read -p "Enter your library, please:" library
read -p "Enter your address, please:" address
addr2line = /opt/fsl-imx-fb/4.14-sumo/sysroots/cortexa9hf-neon-poky-linux-gnueabi/usr/lib/opkg/alternatives/addr2line
$(addr2line) -Cif -e $(library) $(address)
