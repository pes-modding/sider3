-- Stadium switcher example:
-- for English Super Cup, go to Bombonera, and set a rainy winter day
-- for UEFA Champions Leaguge Final - to Camp Nou, daytime

local m = {}

function m.set_stadium(ctx, options)
    if ctx.tournament_id == 101 then
        log("English Super Cup: switching to Bombonera")
        return 28  -- return stadium id to switch stadium

    elseif ctx.tournament_id == 13 and ctx.match_info == 53 then
        log("UEFA CL Final: switching to Camp Nou")
        return { stadium = 2 }   -- returning table also works
    end
end

function m.set_stadium_options(ctx, options)
    if ctx.tournament_id == 101 then
        log("English Super Cup: it is a rainy winter day ...")

        options.timeofday = 0 -- Day
        options.weather = 1   -- Rain
        options.season = 1    -- Winter

        -- return the options table to indicate
        -- that this change is final. This stops processing
        -- of the event and modules further down the list
        -- will not receive this event.
        return options

    elseif ctx.tournament_id == 13 and ctx.match_info == 53 then
        log("UEFA CL Final: it is daytime, folks!")
        return { timeofday = 0 }   -- UCL final at day-light
    end
end

function m.init(ctx)
   ctx.register("set_stadium", m.set_stadium)
   ctx.register("set_stadium_options", m.set_stadium_options)
end

return m
