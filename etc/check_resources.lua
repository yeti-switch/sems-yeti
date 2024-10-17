
local function rep2num(reply)
  if reply == nil then
    return 0
  end

  if type(reply) == 'table' then
    local res = 0
    for _, v in pairs(reply) do
        res = res + rep2num(v) end
    return res
  end

  return tonumber(reply)
end

local ret = {}
local now = tonumber(ARGV[1])
local i = 2

for _, key in ipairs(KEYS) do
  if key:byte(2) == 108 then
    table.insert(ret, #redis.call('ZRANGE', key, now - tonumber(ARGV[i]), now, 'BYSCORE'))
    i = i + 1
  else
    local rep = redis.call('HVALS', key)
    table.insert(ret, rep2num(rep))
  end
end
return ret
