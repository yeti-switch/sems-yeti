local node_id = KEYS[1]

for i,k in ipairs(redis.call('KEYS', 'r:*:*')) do
    redis.call('HSET', k, node_id, '0')
end
