-- appends CDR (writecdr arguments) as JSON array line to spool/cdr.jsonl
-- (path is relative to the SEMS working directory: e2e_tests)

local CDR_FILE = "spool/cdr.jsonl"

local escapes = { ['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t' }

local function encode(v)
    local t = type(v)
    if t == "nil" then
        return "null"
    elseif t == "boolean" then
        return tostring(v)
    elseif t == "number" then
        if v ~= v or v == math.huge or v == -math.huge then return "null" end
        if math.type(v) == "integer" then return tostring(v) end
        return string.format("%.17g", v)
    elseif t == "string" then
        return '"' .. v:gsub('[%c"\\]', function(c)
            return escapes[c] or string.format("\\u%04x", c:byte())
        end) .. '"'
    elseif t == "table" then
        local out = {}
        if #v > 0 or next(v) == nil then
            for i = 1, #v do out[#out + 1] = encode(v[i]) end
            return "[" .. table.concat(out, ",") .. "]"
        end
        for k, val in pairs(v) do
            out[#out + 1] = encode(tostring(k)) .. ":" .. encode(val)
        end
        return "{" .. table.concat(out, ",") .. "}"
    end
    return encode(tostring(v))
end

function writecdr(query, ...)
    local args = {}
    local n = select('#', ...)
    for i = 1, n do args[i] = encode((select(i, ...))) end

    local f = io.open(CDR_FILE, "a")
    if f then
        f:write("[" .. table.concat(args, ",") .. "]\n")
        f:close()
    end
    return {}
end

return writecdr
