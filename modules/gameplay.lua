--[[
Gameplay modification example
Credits: gameplay research by nesa24
Requires: sider.dll 3.4.0.0
--]]

-- log current gameplay values
local function log_gameplay_values()
    log(string.format("gameplay.ball_physics = %s", gameplay.ball_physics))
    log(string.format("gameplay.ball_weight = %s", gameplay.ball_weight))
    log(string.format("gameplay.ball_bounce = %s", gameplay.ball_bounce))
    log(string.format("gameplay.speed = %s", gameplay.speed))
    log(string.format("gameplay.speed_global = %s", gameplay.speed_global))
    log(string.format("gameplay.shooting_power = %s", gameplay.shooting_power))
end

local function init(ctx)
    log("ORIGINAL:")
    log_gameplay_values()

    gameplay.ball_weight = 700.0   -- heavy ball
    gameplay.shooting_power = 0.9  -- increased shooting power

    log("CURRENT:")
    log_gameplay_values()
end

return { init = init }
