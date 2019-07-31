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

