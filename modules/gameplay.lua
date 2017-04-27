--[[
Gameplay modification example
Credits: gameplay research by nesa24
Requires: sider.dll 3.4.0.0
--]]

local function log_gameplay_values()
    log(string.format("gameplay.ball_physics = %s", gameplay.ball_physics))
    log(string.format("gameplay.ball_weight = %s", gameplay.ball_weight))
    log(string.format("gameplay.ball_bounce = %s", gameplay.ball_bounce))
    log(string.format("gameplay.speed = %s", gameplay.speed))
    log(string.format("gameplay.speed_global = %s", gameplay.speed_global))
    log(string.format("gameplay.shooting_power = %s", gameplay.shooting_power))
end

local function gameplay_tweaks(ctx)
    gameplay.ball_weight = 700.0   -- heavy ball
    gameplay.shooting_power = 0.9  -- increased shooting power

    -- log current gameplay values
    log_gameplay_values()
end

local function init(ctx)
    -- log original gameplay values
    log_gameplay_values()

    -- we will modify gameplay settings before each match
    ctx.register("set_home_team", gameplay_tweaks)
end

return { init = init }
