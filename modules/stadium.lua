-- Stadium switcher: for English Super Cup

local m = {}

function m.set_stadium(ctx, options)
    if ctx.tournament_id == 101 then
        log("Switching to Camp Nou on a rainy winter day")
        -- English Super Cup
        options.stadium = 2   -- Camp Nou
        options.timeofday = 0 -- Day
        options.weather = 1   -- Rain
        options.season = 1    -- Winter
        return options
    end
end

function m.init(ctx)
   ctx.register("set_stadium", m.set_stadium)
end

return m
