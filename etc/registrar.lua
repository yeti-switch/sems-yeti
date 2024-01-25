#!lua name=registrar

-- a:auth_id: (SET)
--   * contact_uri1
--   * contact_uri2
-- c:contact_uri1 (expires in TTL)
--   * path: 127.0.0.1:5060
local function get_bindings(id, auth_id, cleanup, ...)
    local ret = {}

    for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        local contact_key = 'c:'..id..':'..c
        local expires = redis.call('TTL', contact_key)
        if expires > 0 then
            local hash_data = redis.call('HMGET',contact_key, ...)
            local d = { c, expires, contact_key, hash_data[1], hash_data[2], hash_data[3], hash_data[4] }
            ret[#ret+1] = d
        elseif cleanup then
            -- cleanup obsolete SET members
            redis.call('SREM',auth_id, c)
        end
    end

    return ret
end

local function load_contacts()
    local data = {}
    local r = { 0 }
    local e
    repeat
        r = redis.call('SCAN', r[1], 'MATCH', 'c:*')
        for k,v in pairs(r[2]) do
            e = redis.call('HMGET',v,'node_id','path','interface_id')
            e[#e + 1] = v
            data[#data +1] = e
        end
    until(tonumber(r[1]) == 0)

    return data
end

-- keys: auth_id list
local function aor_lookup(keys)
    local ret = {}

    for i,id in ipairs(keys) do
        local cset = { }
        local auth_id = 'a:'..id
        for j,c in ipairs(redis.call('SMEMBERS',auth_id)) do
            local contact_key = 'c:'..id..':'..c
            if redis.call('EXISTS', contact_key) then
                cset[#cset + 1] = c
                cset[#cset + 1] = redis.call('HGET',contact_key,'path')
            end
        end

        if next(cset) ~= nil then
            ret[#ret + 1] = tonumber(id)
            ret[#ret + 1] = cset
        end
    end

    return ret
end

local function rpc_aor_lookup(keys)
    local ret = {}
    local aor_keys = {}

    if next(keys) == nil then
        local r = { 0 }
        repeat
            r = redis.call('SCAN', r[1], 'MATCH', 'a*')
            for k,v in pairs(r[2]) do
                aor_keys[tonumber(string.sub(v,3))] = 1
            end
        until(tonumber(r[1]) == 0)
    else
        for k,v in ipairs(keys) do aor_keys[v] = 1 end
    end

    for id in pairs(aor_keys) do
        ret[#ret + 1] = tonumber(id)
        ret[#ret + 1] = get_bindings(id, 'a:'..id, false, 'node_id','interface_id','agent','path')
    end

    return ret
end

-- auth_id [ expires [ contact node_id interace_id user_agent path ] ]
local function register(keys, args)
    local id = keys[1]
    local auth_id = 'a:'..id

    if not args[1] then
        -- no expires. fetch all bindings
        return get_bindings(id, auth_id, true, 'path', 'interface_id')
    end

    local expires = tonumber(args[1])
    local contact = args[2]

    if not expires then
        return 'Wrong expires value'
    end

    if expires==0 then
        if not contact then
            -- remove all bindings
            for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
                redis.call('DEL', 'c:'..id..':'..c)
            end
            redis.call('DEL', auth_id)
            return nil
        else
            local contact_key = 'c:'..id..':'..contact
            -- remove specific binding
            redis.call('SREM', auth_id, contact)
            redis.call('DEL', contact_key)
            return get_bindings(id, auth_id, true, 'path', 'interface_id')
        end
    end

    local contact_key = 'c:'..id..':'..contact
    local node_id = args[3]
    local local_interface_id = args[4]
    local user_agent = args[5]
    local path = args[6]

    if not user_agent then
        user_agent = ''
    end

    if not path then
        path = ''
    end

    -- cleanup obsolete set members
    for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        if 0==redis.call('EXISTS', 'c:'..id..':'..c) then
            redis.call('SREM', auth_id, c)
        end
    end

    -- check for max allowed bindings
    if redis.call('SCARD', auth_id) >= 10 then
        return 'Too many registered contacts'
    end

    -- add binding
    redis.call('SADD', auth_id, contact)
    redis.call('HMSET', contact_key,
        'node_id',node_id,
        'interface_id',local_interface_id,
        'agent',user_agent,
        'path',path)

    -- set TTL
    redis.call('EXPIRE', contact_key, expires)

    -- return active bindings
    return get_bindings(id, auth_id, true, 'path', 'interface_id')
end

redis.register_function("load_contacts", load_contacts)
redis.register_function("register", register)
redis.register_function{function_name="aor_lookup",
                        callback=aor_lookup,
                        flags={"no-writes"}}
redis.register_function{function_name="rpc_aor_lookup",
                        callback=rpc_aor_lookup,
                        flags={"no-writes"}}

