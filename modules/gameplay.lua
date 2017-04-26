--[[
Gameplay modification example: ball weight
Credits: gameplay research by nesa24
Requires: sider.dll 3.4.0.0
--]]

-- original ball weight is 1000.0
-- values:  heavier ball < 1000.0 < lighter ball

local function gameplay_tweaks(ctx)
    local ball_weight = gameplay.get_ball_weight()
    log(string.format("Ball weight WAS: %0.3f", ball_weight))

    ball_weight = 700.0 -- we will use a heavy ball
    gameplay.set_ball_weight(ball_weight)

    -- verify that new value was set successfully
    ball_weight = gameplay.get_ball_weight()
    log(string.format("Ball weight NOW: %0.3f", ball_weight))
end

local function init(ctx)
    -- we will set the ball weight before each match
    ctx.register("set_home_team", gameplay_tweaks)
end

return { init = init }
