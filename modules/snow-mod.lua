-- Snow/Rain switcher, version 1.0
-- idea: Ethan2, kilay
-- snow artwork: Ethan2 and others
-- module written by: juce
--
-- Notes: make sure to register this module ABOVE stadium-server in sider.ini

local snowroot = ".\\content\\snow-mod\\"
local snow

function make_key(ctx, filename)
    if snow then
        local fn = string.gsub(filename, "st%d%d%d", "st029")
        return fn
    end
end

function get_filepath(ctx, filename, key)
    if key then
        return snowroot .. key
    end
end

function set_conditions(ctx, options)
    snow = false
    if options.season == 1 and options.weather == 1 then
        -- it is winter and bad weather, so choose randomly: snow or rain
        local n = math.random(1,10)
        snow = (n >= 5)
        log(string.format("snow: %s (n=%d)", snow, n))

        -- enforce weather effects: falling snow/rain
        options.weather_effects = 2
        return options
    end
end

function init(ctx)
    if snowroot:sub(1,1) == "." then
        snowroot = ctx.sider_dir .. snowroot
    end
    math.randomseed(os.time())  -- seed random generator
    ctx.register("set_conditions", set_conditions)
    ctx.register("set_conditions_for_replay", set_conditions)
    ctx.register("livecpk_make_key", make_key)
    ctx.register("livecpk_get_filepath", get_filepath)
end

return { init = init }
