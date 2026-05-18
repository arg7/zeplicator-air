#!/bin/bash

cluster/cluster-ctl.sh stop
rm /tmp/zep*.log
make install
cluster/cluster-destroy.sh
cluster/cluster-init.sh --zfs
cluster/cluster-ctl.sh start
