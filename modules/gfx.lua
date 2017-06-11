--[[
Graphics modification example
Credits: graphics research by nesa24
Requires: sider.dll 3.5.0.0
--]]

local function get_gfx_settings(ctx)
    local t = {}
    for line in io.lines(ctx.sider_dir .. "\\gfx.ini") do
        local name, value = string.match(line, "^([%w_]+)%s*=%s*([-%d.]+)")
        if name and value then
            t[name] = tonumber(value)
        end
    end
    return t
end

local function gfx_tweaks(ctx)
    local settings = get_gfx_settings(ctx)
    for k,v in pairs(settings) do
        local old_v = gfx[k]
        gfx[k] = v
        log(string.format("%s: %s --> %s", k, old_v, gfx[k]))
    end
end

local function init(ctx)
    -- we will modify gfx settings before each match
    ctx.register("set_home_team", gfx_tweaks)
end

return { init = init }
