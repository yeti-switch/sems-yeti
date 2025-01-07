-- script to remove obsolete rl:*,r:* keys
-- * iterate rl:* keys
--   * delete key if no entries within [now-1day, now] range for it
-- * iterate r:* keys
--    * delete key if all values in the hash are 0
-- usage:
-- $ redis-cli --eval yeti_rl_cleanup.lua

local removed_keys = {}

local now = tonumber(redis.call('TIME')[1])
local cursor = 0
local data = {}

-- process rl:* keys
repeat
    cursor,data = unpack(redis.call('SCAN', cursor, 'MATCH', 'rl:*'))
    for _,k in pairs(data) do
        local ret = redis.call('ZRANGEBYSCORE', k, now-86400, now)
        if next(ret) == nil then
            redis.call('DEL', k)
            table.insert(removed_keys, k)
        end
    end
until cursor=='0'

-- process r:* keys
cursor = 0
repeat
    cursor,data = unpack(redis.call('SCAN', cursor, 'MATCH', 'r:*'))
    for _,k in pairs(data) do
        local ret = redis.call('HVALS', k)
        local has_non_zero = false
        for _,k in pairs(ret) do
            if k ~= '0' then
                has_non_zero = true
                break
            end
        end

        if not has_non_zero then
            redis.call('DEL', k)
            table.insert(removed_keys, k)
        end
    end
until cursor=='0'

return removed_keys
