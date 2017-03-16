--[[ 

Trophy-server
version 0.1 by juce
 
The principle of trophy server is as follows:

#1. we temporarily switch the tournament id at the trophy-check event.
    This allows us to have trophies for those tournaments in the game that
    are unlicensed and do not have appropriate cut-scenes.
    (See doc/tournaments.txt file for a list of some tournament ids.)

#2. we use separate content folders for each tournament that we
    have a trophy for. This way, we can actually fully style the pre-match
    and post-match scenes to match the tournament, without affecting other
    tournaments: trophy itself, celebration boards, banners, etc.

--]]


local fileroot = ".\\content\\trophy-server"
local switch_map = {
    [39] = 33,     -- 39:  English League
    [101] = 144,   -- 101: English Super Cup
}

-- current (actual) tournament id
-- nil, if we do not have it in switch_map
local tid

local function switch_tournament(ctx, tournament_id)
    local rep_id = switch_map[tournament_id]
    tid = rep_id and tournament_id or nil
    if rep_id then
        log(string.format(
            "switching tournament_id: %d --> %d", tournament_id, rep_id))
    else
        -- do not switch, but log the tournament id so that
        -- we can add this information to tournaments.txt and
        -- eventually have a complete list of ids
        log(string.format("tournament_id: %d", tournament_id))
    end
    return rep_id or tournament_id
end

local function make_key(ctx, filename)
    if tid then
        return string.format("%d:%s", tid, filename)
    end
end

local function get_filepath(ctx, filename, key)
    if tid then
        return string.format("%s\\%d\\%s", fileroot, tid, filename)
    end
end

local function init(ctx)
    if fileroot:sub(1,1)=='.' then
        -- assume relative to sider dir
        fileroot = ctx.sider_dir .. fileroot
    end
    log(string.format("fileroot: %s", fileroot))
    ctx.register("tournament_check_for_trophy", switch_tournament)
    ctx.register("livecpk_make_key", make_key)
    ctx.register("livecpk_get_filepath", get_filepath)
end

return { init = init }
