"""helpers to build yeti routing profiles (rows of 'getprofile' result)"""

YETI = ("127.0.0.1", 5060)
# SEMS with yeti enable_auth_feedback (conftest SEMS_VARIANTS "auth_feedback")
YETI_AUTH_FEEDBACK = ("127.0.0.1", 5160)

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


# registered AoRs (SBCCallProfile::RegisteredAorMode)
REGISTERED_AOR_MODE_DISABLED = 0
REGISTERED_AOR_MODE_AS_IS = 1
REGISTERED_AOR_MODE_REPLACE_RURI_TRANSPORT_INFO = 2

# incoming auth credentials (etc/db_map/load_incoming_auth.json). yeti uses credentials id as AoR id
AOR1 = {"id": 1, "user": "test", "password": "test"}
AOR2 = {"id": 2, "user": "tusr", "password": "tpwd"}
AOR_NEVER_REGISTERED_ID = 100

# gateways with push_token (etc/db_map/load_gateway_attributes_cache.json, '<type>:<value>')
GW_PUSH_WEBHOOK = 10       # 3:webhook-token
GW_PUSH_FCM = 11           # 0:fcm-token
GW_PUSH_APNS = 12          # 1:apns-token
GW_PUSH_APNS_SANDBOX = 13  # 2:apns-sandbox-token

# translation of DC_NOT_REGISTERED (131) from etc/db_map/load_disconnect_code_refuse.json
NOT_REGISTERED = (480, "Gateway not registered")


def aor_profile(aor_id, mode=REGISTERED_AOR_MODE_AS_IS, ruri="sip:aor-user@unknown.invalid", **fields):
    """routing profile to the registered AoR"""
    return {"ruri": ruri, "registered_aor_id": aor_id, "registered_aor_mode_id": mode, **fields}


class Routing:
    """
    controls response of yeti routing query (prepared statement 'getprofile')
    served by postgresql_proxy. profiles are rows of the routing function result
    """

    QUERY = "getprofile"

    def __init__(self, rpc):
        self.rpc = rpc

    def set_profiles(self, profiles):
        ret = self.rpc.call("postgresql_proxy.map.insert", [self.QUERY, profiles])
        assert not ret, f"postgresql_proxy.map.insert failed: {ret}"

    def reset(self):
        """routing query fails like it is not mapped at all"""
        ret = self.rpc.call("postgresql_proxy.map.insert", [self.QUERY, None, "no routing configured by test"])
        assert not ret, f"postgresql_proxy.map.insert failed: {ret}"
