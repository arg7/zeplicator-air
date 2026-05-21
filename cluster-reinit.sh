#!/bin/bash

cluster/cluster-ctl.sh stop
rm /tmp/zep*.log
make install
cluster/cluster-destroy.sh --force
cluster/cluster-init.sh --zfs --resume-test
cluster/cluster-ctl.sh start
