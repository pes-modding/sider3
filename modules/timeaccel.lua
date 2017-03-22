-- Time accelerator: for non-exhibition matches

local m = {}

function m.set_match_time(ctx, minutes)
    if ctx.tournament_id > 5 then
        -- non-exhibition
        local acc = 1
        log(string.format("Accelerating match time: %d --> %d minutes",
            minutes, acc))
        return acc
    end
end

function m.init(ctx)
   ctx.register("set_match_time", m.set_match_time)
end

return m
