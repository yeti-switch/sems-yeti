for _,v in ipairs(ARGV) do
  local t = {}
  for i in string.gmatch(v, "%S+") do
     table.insert(t, i)
  end
  redis.call('HINCRBY', t[1], t[2], t[3])
end
