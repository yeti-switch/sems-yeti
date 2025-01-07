-- script to remove obsolete rl:* keys
-- * iterate rl:* keys
--   * delete key if no entries within [now-1day, now] range for it
-- usage:
-- $ redis-cli --eval rl_cleanup.lua

local removed_keys = {}

local now = tonumber(redis.call('TIME')[1])
local cursor = 0
local data = {}

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

return removed_keys
