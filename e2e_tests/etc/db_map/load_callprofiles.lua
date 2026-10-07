-- profile without/empty/null cache_id will be applied to all profiles at the very end
-- should be unique in response
local common_profile = {
    enable_rtprelay = true,
    aleg_codecs_group_id =  1,
    bleg_codecs_group_id =  1,
    dump_level_id = 1,
    lega_gw_cache_id = 1,
    legb_gw_cache_id = 1
}

function load_callprofiles()
    return {
        common_profile
    }
end

return load_callprofiles


