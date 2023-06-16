#!/bin/bash

set -e

cd $(dirname "${BASH_SOURCE[0]}")

BUILD_DIR=./build
TEST_TMP_DIR=$BUILD_DIR/unit_tests

SEMS_TESTER=/usr/bin/sems-tester
[ "$GDB" == "1" ] && SEMS_TESTER="gdb -q -ex r --args $SEMS_TESTER"

SEMS_TESTER_CFG=./unit_tests/etc/sems_test.cfg

MODULE_PREFIX=YetiTest
DEFAULT_FILTER=$MODULE_PREFIX.*:$MODULE_PREFIX/*

for d in rsr logs lib dump record; do
    mkdir -p $TEST_TMP_DIR/$d
done

#prepare lib dir
for m in \
$BUILD_DIR/src/yeti_unit.so \
/usr/lib/sems/plug-in/wav.so \
/usr/lib/sems/plug-in/uac_auth.so \
/usr/lib/sems/plug-in/jsonrpc.so \
/usr/lib/sems/plug-in/postgresql.so \
/usr/lib/sems/plug-in/registrar_client.so
do
    name=$(basename $m)
    cp -uv $m $TEST_TMP_DIR/lib/${name//"_unit"/}
done

if [ $# -gt 0 ]; then
    filter=$1
    shift

    if [ $filter == "all" ]; then
        cmd="$SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_filter=$DEFAULT_FILTER $@"
    else
        if [[ $filter == *"."* || $filter == *"/"* ]]; then
            cmd="$SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_also_run_disabled_tests --gtest_filter=$filter $@"
        else
            cmd="$SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_also_run_disabled_tests --gtest_filter=$MODULE_PREFIX.$filter:$MODULE_PREFIX/$filter $@"
        fi
    fi
else
    cmd="$SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_filter=$DEFAULT_FILTER --gtest_list_tests"
fi

echo $cmd
exec $cmd
