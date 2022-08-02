#!/bin/bash

set -e

cd $(dirname "${BASH_SOURCE[0]}")

BUILD_DIR=./build
TEST_TMP_DIR=$BUILD_DIR/unit_tests

SEMS_TESTER=/usr/bin/sems-tester
SEMS_TESTER_CFG=./unit_tests/etc/sems_test.cfg

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

$SEMS_TESTER -c $SEMS_TESTER_CFG --gtest_also_run_disabled_tests --gtest_filter="YetiTest.*" $@
