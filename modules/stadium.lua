-- Stadium switcher example:
-- for English Super Cup, go to Bombonera.
-- for UEFA Champions Leaguge Final - to Camp Nou

local m = {}

function m.set_stadium(ctx, options)
    if ctx.tournament_id == 101 then
        log("Switching to Bombonera on a rainy winter day")

        options.stadium = 28  -- Stadium id (Bombonera)
        options.timeofday = 0 -- Day
        options.weather = 1   -- Rain
        options.season = 1    -- Winter

        -- return the options table to indicate
        -- that this change is final. This stops processing
        -- of the event and modules further down the list
        -- will not receive this event.
        return options

    elseif ctx.tournament_id == 13 and ctx.match_info == 53 then
        log("UEFA CL Final: switching to Camp Nou")

        -- don't change weather/season/timeoday, only stadium
        options.stadium = 2
        return options
    end
end

function m.init(ctx)
   ctx.register("set_stadium", m.set_stadium)
end

return m
