local type = KEYS[1]
local id = KEYS[2]

local function ternary(cond , T , F)
    if cond then return T else return F end
end

local pattern = 'r:'..ternary(tonumber(type)>=0, type, '*')..':'..ternary(tonumber(id)>=0, id, '*')
local ret = {}
for i, key in ipairs(redis.call('KEYS', pattern)) do
    local all = {}
    for _, node_id_and_val in ipairs(redis.call('HGETALL', key)) do
      table.insert(all, tonumber(node_id_and_val))
    end
    table.insert(ret, {key, all})
end

return ret
