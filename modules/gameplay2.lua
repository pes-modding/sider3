--[[
Gameplay modification example
Credits: gameplay research by nesa24
Requires: sider.dll 3.4.0.0
--]]

local function get_gameplay_settings(ctx)
    local t = {}
    for line in io.lines(ctx.sider_dir .. "\\gameplay.txt") do
        local name, value = string.match(line, "^([%w_]+)%s*=%s*([-%d.]+)")
        if name and value then
            t[name] = tonumber(value)
        end
    end
    return t
end

local function gameplay_tweaks(ctx)
    local settings = get_gameplay_settings(ctx)
    for k,v in pairs(settings) do
        local old_v = gameplay[k]
        gameplay[k] = v
        log(string.format("%s: %s --> %s", k, old_v, gameplay[k]))
    end
end

local function init(ctx)
    -- we will modify gameplay settings before each match
    ctx.register("set_home_team", gameplay_tweaks)
end

return { init = init }
