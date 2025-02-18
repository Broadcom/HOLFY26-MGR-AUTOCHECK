#!/bin/sh

# 03/22/2021 modified to create 2 partitions to match the Windows mechanism
# idisksrv mounts the 2nd partition to retrieve the AutoCheck zip
# adjusted block range to UDEV rule on idisksrv
# 07/25/2021 check for mounted /mnt/idisk and return success (more reliable approach)

# find the 1 GB disk
dev=`cat /proc/partitions | grep 1048576 | awk  '{print $4}'`
if [ -z $dev  ] ; then
	echo "No iDisk present. Abort."
	exit 1
else
	echo "Preparing iDisk on /dev/${dev}..."
fi

# create the "dummy" reserved partition
# and then
# create the GPT Microsoft basic partion
/usr/sbin/fdisk /dev/${dev} <<EOF
g
n
1
2048
+30MB
t
10
n
2
65664
2097100
t
2
11
w
EOF

# format it FAT
idisk=/mnt/idisk
/usr/sbin/mkfs.fat /dev/${dev}2

# create the mount point if needed
if [ ! -d $idisk ];then
	mkdir $idisk
fi

# mount it
/usr/bin/mount -t vfat /dev/${dev}2 /mnt/idisk/ -o rw,uid=holuser,gid=holuser

# verify /mnt/idisk is mounted and if so return success
result=`mount | grep /mnt/idisk`
if [ -z result ] ; then
	echo "iDisk FAILED!"
	exit 1
else
	echo "iDisk ready"
	exit 0
fi

