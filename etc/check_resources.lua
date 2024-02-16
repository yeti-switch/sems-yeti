
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
for _, key in ipairs(ARGV) do
  local rep = redis.call('HVALS', key);
  table.insert(ret, rep2num(rep))
end
return ret
