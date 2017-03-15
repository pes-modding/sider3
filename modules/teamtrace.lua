-- Team tracer
-- prints out the team ids, as they are set for a match

local function set_home(ctx, id)
    log(string.format("home team: %d", id))
end

local function set_away(ctx, id)
    log(string.format("away team: %d", id))
end

return { 
    init = function(ctx)
       ctx.register("set_home_team", set_home); 
       ctx.register("set_away_team", set_away); 
    end
}
