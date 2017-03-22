-- Stadium switcher example:
-- for English Super Cup, go to Camp Nou.

local m = {}

function m.set_stadium(ctx, options)
    if ctx.tournament_id == 101 then
        log("Switching to Camp Nou on a rainy winter day")

        options.stadium = 2   -- Camp Nou
        options.timeofday = 0 -- Day
        options.weather = 1   -- Rain
        options.season = 1    -- Winter

        -- return the options table to indicate
        -- that this change is final. This stops processing
        -- of the event and modules further down the list
        -- will not receive this event.
        return options
    end
end

function m.init(ctx)
   ctx.register("set_stadium", m.set_stadium)
end

return m
