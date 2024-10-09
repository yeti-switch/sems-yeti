local os = require('os')

function log(msg)
    print(os.date('%F %T')..' [lua] '..msg)
end

-- this profile MUST always be the last one in the profiles list
local rejecting_profile = {
    disconnect_code_id = 113
}

-- you can also define all expected parameters explicitly
function getprofile(query, ...)
    log('query: '..query)

    log('args count: '..select('#',...))

    -- set 'postgresql_debug·=·yes' for yeti module to check params positions/meaning
    local node_id, pop_id = select(1,...)
    log('node_id: '..node_id)
    log('pop_id: '..pop_id)

    log('protocol_id: '..select(3,...))
    log('from_name: '..select(9,...))
    log('to_name: '..select(12,...))
    log('input_interface_name: '..select(22,...))

    local profile = {
        ruri = "sip:42@127.0.0.1:6050",
        aleg_codecs_group_id =  1,
        bleg_codecs_group_id =  1
    }

    return {
        profile,
        rejecting_profile
    }
end

return getprofile
