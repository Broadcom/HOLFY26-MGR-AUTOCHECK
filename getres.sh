#!/bin/bash
XAUTHORITY=`cat /tmp/XAUTHORITY`
export XAUTHORITY
/usr/bin/xrandr --current --display :0 | grep \*+ | cut -f4 -d ' '
