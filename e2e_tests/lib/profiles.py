"""helpers to build yeti routing profiles (rows of 'getprofile' result)"""

YETI = ("127.0.0.1", 5060)

# refusing profile, the last one in routing result: 113 -> '404 No routes'
NO_ROUTES = {"disconnect_code_id": 113}

# gateways from etc/db_map/load_gateway_attributes_cache.json (loaded to both A-leg and B-leg caches)
GW_EARLY_MEDIA_DISABLED = 1
GW_EARLY_MEDIA_NOT_AUTHORIZED_ONLY = 2
GW_EARLY_MEDIA_ALWAYS = 3


def route_to(gw, user="term-user", **fields):
    """routing profile sending the call to the gateway UAS. fields override common profile ones"""
    return {"ruri": f"sip:{user}@{gw.ip}:{gw.port}", **fields}


def connect_call(routing, caller, term_gw, **fields):
    """routes the call to term_gw with profile fields and returns answered INVITE reply of the caller"""
    routing.set_profiles([route_to(term_gw, **fields), NO_ROUTES])
    reply = caller.invite(YETI)
    assert reply is not None, "no final reply for INVITE"
    assert reply.code == 200, reply.raw
    assert term_gw.wait_request("ACK", call_id=term_gw.call_id) is not None, "no ACK on termination side"
    return reply
