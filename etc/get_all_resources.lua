local type = KEYS[1]
local id = KEYS[2]

local function ternary(cond , T , F)
    if cond then return T else return F end
end

local pattern = 'r*:'..ternary(tonumber(type)>=0, type, '*')..':'..ternary(tonumber(id)>=0, id, '*')
local ret = {}
for i, key in ipairs(redis.call('KEYS', pattern)) do
    local data = {}
    if key:byte(2) == 108 then
      data = redis.call('ZCARD', key)
    else
      for _, node_id_and_val in ipairs(redis.call('HGETALL', key)) do
        table.insert(data, tonumber(node_id_and_val))
      end
    end
    table.insert(ret, {key, data})
end

return ret
