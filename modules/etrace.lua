-- Event tracer
-- prints event and context info, reacting to various events

local m = {}

local function t2s(t)
    local parts = {}
    for k,v in pairs(t) do
        parts[#parts + 1] = string.format("%s=%s", k, v)
    end
    table.sort(parts) -- sort alphabetically
    return string.format("{%s}", table.concat(parts,", "))
end

function m.set_home(ctx, id)
    log(string.format("home team: %d", id))
    log(string.format("ctx: %s", t2s(ctx)))
end

function m.set_away(ctx, id)
    log(string.format("away team: %d", id))
    log(string.format("ctx: %s", t2s(ctx)))
end

function m.set_match_time(ctx, minutes)
    log(string.format("match time: %d", minutes))
    log(string.format("ctx: %s", t2s(ctx)))
end

function m.set_tid(ctx, tid)
    log(string.format("tournament_id: %d", tid))
    log(string.format("ctx: %s", t2s(ctx)))
end

function m.set_stadium(ctx, options)
    log(string.format("stadium: %s", options.stadium))
    log(string.format("ctx: %s", t2s(ctx)))
end

function m.set_stadium_options(ctx, options)
    log(string.format("stadium options: %s", t2s(options)))
    log(string.format("ctx: %s", t2s(ctx)))
end

function m.enter_edit_mode(ctx)
    log("Entered EDIT mode")
    log(string.format("ctx: %s", t2s(ctx)))
end

function m.exit_edit_mode(ctx)
    log("Exited EDIT mode")
    log(string.format("ctx: %s", t2s(ctx)))
end

function m.init(ctx)
   ctx.register("set_home_team", m.set_home)
   ctx.register("set_away_team", m.set_away)
   ctx.register("set_tournament_id", m.set_tid)
   ctx.register("set_match_time", m.set_match_time)
   ctx.register("set_stadium", m.set_stadium)
   ctx.register("set_stadium_options", m.set_stadium_options)
   ctx.register("enter_edit_mode", m.enter_edit_mode)
   ctx.register("exit_edit_mode", m.exit_edit_mode)
end

return m
