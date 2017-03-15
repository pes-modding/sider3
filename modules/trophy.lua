-- Trophy-server
-- version 0.2

local fileroot = ".\\content\\trophy-server"
local switch_map = {
    [39] = 33,     -- English League
    [101] = 144,   -- English Super Cup
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
    log("initializing ...")
    if fileroot:sub(1,1)=='.' then
        fileroot = ctx.sider_dir .. fileroot
    end
    log(string.format("fileroot: %s", fileroot))
    ctx.register("tournament_check_for_trophy", switch_tournament)
    ctx.register("livecpk_make_key", make_key)
    ctx.register("livecpk_get_filepath", get_filepath)
end

return { init = init }
