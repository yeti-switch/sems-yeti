#!/usr/bin/bash

set -e

dst_dir=${DEST:-/etc/yeti/db_map}

gen_map() {
    name=$1
    shift
    query=$@
    dst=$dst_dir/$f.json
    python gen_postgresql_mock_mapping.py "$query" > $dst
    echo "    map_file(\"$query\", \"$dst\")"
}

gen_empty_map() {
    echo "    map(\"$1\", [])"
}

echo 'module "postgresql_mock" {'

for f in \
    check_states \
    load_interface_in \
    load_interface_out \
    load_trusted_lb \
    load_incoming_auth \
    load_resource_types \
    load_codec_groups \
    load_disconnect_code_refuse \
    load_disconnect_code_rerouting \
    load_disconnect_code_rewrite
do
    gen_map $f "SELECT * FROM $f()"
done

f=$dst_dir/load_ip_auth.json
cat > $f <<EOF
[
    {
        "ip": "127.0.0.1",
        "x_yeti_auth": null,
        "require_incoming_auth": false,
        "require_identity_parsing": true
    }
]
EOF
echo "    map_file(\"SELECT * FROM load_ip_auth(\\\$1,\\\$2)\", $f)"

for f in \
    load_radius_accounting_profiles \
    load_radius_profiles \
    load_sensor \
    load_stir_shaken_signing_certificates \
    load_stir_shaken_trusted_certificates \
    load_stir_shaken_trusted_repositories \
    load_disconnect_code_refuse_overrides \
    load_disconnect_code_rerouting_overrides \
    load_disconnect_code_rewrite_overrides
do
    gen_empty_map "SELECT * FROM $f()"
done

gen_empty_map "SELECT init(\\\$1,\\\$2);"
gen_empty_map "SELECT * FROM load_sip_options_probers(\\\$1)"
gen_empty_map "SELECT * FROM load_registrations_out(\\\$1,\\\$2)"

echo '}'
