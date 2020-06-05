#!/bin/sh
killall -9 envset_proc
rm -f instance/server/aspect_policy.cfg
rm -f instance/Teacher/aspect_policy.cfg
yes|cp instance/server/plugin_config.cfg.user instance/server/plugin_config.cfg
yes|cp instance/server/sys_config.cfg.user instance/server/sys_config.cfg
yes|cp instance/server/router_policy.cfg.user instance/server/router_policy.cfg

yes|cp instance/Teacher/sys_config.cfg.user instance/Teacher/sys_config.cfg
yes|cp instance/Teacher/router_policy.cfg.user instance/Teacher/router_policy.cfg
sleep 1

sh run_cube.sh exec_def/_user_server.def &
sleep 1
sh run_cube.sh exec_def/_Teacher_client.def login.msg
