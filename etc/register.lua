-- auth_id contact expires user_agent [path]

local auth_id = 'a:'..KEYS[1]
local contact = ARGV[1]

-- a:auth_id: (SET)
--   * contact_uri1
--   * contact_uri2
-- c:contact_uri1 (expires in TTL)
--   * path: 127.0.0.1:5060

local function get_bindings()
    local ret = {}

    for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        local d = { c }
        local contact_key = 'c:'..auth_id..':'..c
        local expires = redis.call('TTL', contact_key)

        if expires > 0 then
            d[#d + 1] = expires
            -- d[#d + 1] = redis.call('HGET',auth_id,'path')
            ret[#ret+1] = d
        else
            -- cleanup obsolete SET members
            redis.call('SREM',auth_id, c)
        end
    end

    return ret
end

if not contact then
    return get_bindings()
end

local expires = tonumber(ARGV[2])

if not expires then
    return 'Wrong expires value'
end

local contact_key = 'c:'..auth_id..':'..contact

if expires==0 then
    -- remove all bindings
    for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        redis.call('DEL', 'c:'..auth_id..':'..c)
    end
    redis.call('DEL', auth_id)
    return nil
end

local user_agent = ARGV[3]
local path = ARGV[4]

if not user_agent then
    user_agent = ''
end

if not path then
    path = ''
end

-- check for max allowed bindings
if redis.call('SCARD', auth_id) >= 10 then
    return 'Too many registrations'
end

-- add binding
redis.call('SADD', auth_id, contact)
redis.call('HSET', contact_key, 'agent',user_agent, 'path',path)

-- set TTL
redis.call('EXPIRE', contact_key, expires)

-- return active bindings
return get_bindings()
