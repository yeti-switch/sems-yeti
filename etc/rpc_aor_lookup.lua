-- KEYS: auth_id list

local ret = {}
local keys = {}

if next(KEYS) == nil then
    local r = { 0 }
    repeat
        r = redis.call('SCAN', r[1], 'MATCH', 'a*')
        for k,v in pairs(r[2]) do
            keys[tonumber(string.sub(v,3))] = 1
        end
    until(tonumber(r[1]) == 0)
else
    for k,v in ipairs(KEYS) do keys[v] = 1 end
end

for id in pairs(keys) do
    local cset = { }
    local auth_id = 'a:'..id
    for j,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        local contact_key = 'c:'..id..':'..c
        local expires = redis.call('TTL', contact_key)
        if expires > 0 then
            local key_data = redis.call('HMGET',contact_key,'node_id','interface_id','agent','path')
            cset[#cset +1] = { c, expires, key_data[1], key_data[2], key_data[3], key_data[4] }
        end
    end

    if next(cset) ~= nil then
        ret[#ret + 1] = tonumber(id)
        ret[#ret + 1] = cset
    end
end

return ret
