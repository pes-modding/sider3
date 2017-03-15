-- Team tracer
-- prints out the team ids, as they are set for a match

local m = {}

function m.set_home(ctx, id)
    log(string.format("home team: %d", id))
end

function m.set_away(ctx, id)
    log(string.format("away team: %d", id))
end

function m.init(ctx)
   ctx.register("set_home_team", m.set_home); 
   ctx.register("set_away_team", m.set_away); 
end

return m
