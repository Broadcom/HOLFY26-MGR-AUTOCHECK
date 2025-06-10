#! /bin/sh
# version 1.0 - 25-March 2024

# the only job of this script is to pull the latest AutoCheck code


cd /home/holuser/autocheck
ctr=0
while true;do
   if [ $ctr -gt 30 ];then
      echo "FATAL could not perform git pull." >> ${logfile}
      exit  # do we exit here or just report?
   fi
   git pull origin master
   if [ $? = 0 ];then
      break
   else
      echo "Could not complete git pull. Will try again."
  fi
  ctr=`expr $ctr + 1`
  sleep 5
done

