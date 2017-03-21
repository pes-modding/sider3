-- Eevent tracer
-- prints context info reading to events

local m = {}

local function log_context(ctx)
    local parts = {}
    for k,v in pairs(ctx) do
        parts[#parts + 1] = string.format("%s=%s", k, v)
    end
    log(string.format("ctx: %s", table.concat(parts,",")))
end

function m.set_home(ctx, id)
    log(string.format("home team: %d", id))
    log_context(ctx)
end

function m.set_away(ctx, id)
    log(string.format("away team: %d", id))
    log_context(ctx)
end

function m.set_match_time(ctx, minutes)
    log(string.format("num minutes: %d", minutes))
    log_context(ctx)
end

function m.set_tid(ctx, tid)
    log(string.format("tournament_id: %d", tid))
    log_context(ctx)
end

function m.init(ctx)
   ctx.register("set_home_team", m.set_home); 
   ctx.register("set_away_team", m.set_away); 
   ctx.register("set_tournament_id", m.set_tid); 
   ctx.register("set_match_time", m.set_match_time); 
end

return m
