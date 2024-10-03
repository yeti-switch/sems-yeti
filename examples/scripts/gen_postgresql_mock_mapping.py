#!/usr/bin/env python3

# python gen_postgresql_mock_mapping.py 'SELECT * from load_interface_in()' > /etc/yeti/db_map/load_interface_in.json

import sys
import json
import datetime
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except:
    raise Exception("apt install python3-psycopg2")

SCHEMA_VERSION = 21

db_opts = {
    "host" : "127.0.0.1",
    "port" : 5432,

    "database" : "yeti",
    "user" : "yeti",
    "password" : "yeti",

    "options" : f"-c search_path=public,switch{SCHEMA_VERSION}"
}

class JsonEncoderWithDatetime(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return str(obj)
        return super().default(obj)

if len(sys.argv) < 2:
    print(f"usage:\n    {sys.argv[0]} sql-query")
    raise SystemExit(1)

try:
    with psycopg2.connect(**db_opts) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cmd = ' '.join(sys.argv[1:])
            cur.execute(cmd)
            print(json.dumps(cur.fetchall(), indent=4, cls=JsonEncoderWithDatetime))
except (psycopg2.DatabaseError, Exception) as e:
    print(e, file=sys.stderr)
    raise SystemExit(1)
