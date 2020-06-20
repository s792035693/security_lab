#! /bin/sh
PRO_NAME=/home/sq_centos/cube-userdefine_new/user_login.sh
#PRO_NAME=record_access.sh
#PRO_NAME=record_rw.sh
#PRO_NAME=record_rw_teacher.sh
#PRO_NAME=user_label.sh
#PRO_NAME=user.login.sh

WLAN=ra0
  
while true ; do
  
#    用ps获取$PRO_NAME进程数量
  NUM=`ps aux | grep ${PRO_NAME} | grep -v grep |wc -l`
#  echo $NUM
#    少于1，重启进程
  if [ "${NUM}" -lt "1" ];then
    echo "${PRO_NAME} was killed"
    sh /home/sq_centos/cube-userdefine_new/user_login.sh
#    大于1，杀掉所有进程，重启
  elif [ "${NUM}" -gt "1" ];then
    echo "more than 1 ${PRO_NAME},killall ${PRO_NAME}"
    killall -9 $PRO_NAME
    ${PRO_NAME} -i ${WLAN}
  fi
#    kill僵尸进程
  NUM_STAT=`ps aux | grep ${PRO_NAME} | grep T | grep -v grep | wc -l`
  
  if [ "${NUM_STAT}" -gt "0" ];then
    killall -9 ${PRO_NAME}
    ${PRO_NAME} -i ${WLAN}
  fi
done
  
exit 0
