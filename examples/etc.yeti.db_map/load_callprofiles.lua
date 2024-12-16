-- profile without/empty/null cache_id will be applied to all profiles at the very end
-- should be unique in response
local common_profile = {
    aleg_codecs_group_id =  1,
    bleg_codecs_group_id =  1,
}

-- will be merged into the profile with the same cache_id value returned by DB
local specific_profile = {
    cache_id = "test:42",
    bleg_rel100_mode_id = 1,
}

function load_callprofiles()
    return {
        common_profile,
        specific_profile
    }
end

return load_callprofiles
