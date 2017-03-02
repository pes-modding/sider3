-- Trophy-server
-- version 0.1

local cfg = {
    fileroot = "c:\\Users\\Anton\\Desktop\\Дурак\\trophy-roots\\test2",
    switch_map = {
        [101] = 33,
        [103] = 33,
    },
}

-- current (actual) tournament id
-- nil, if we do not have it in switch_map
local tid

local function switch_tournament(ctx, tournament_id)
    local rep_id = cfg.switch_map[tournament_id]
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
    return filename
end

local function get_filepath(ctx, filename, key)
    if tid then
        return string.format("%s\\%d\\%s", cfg.fileroot, tid, filename)
    end
    return nil
end

local function init(ctx)
    log("initializing ...")
    if cfg.fileroot:sub(1,1)=='.' then
        cfg.fileroot = string.format("%s\\%s", ctx.sider_dir, cfg.fileroot)
    end
    log(string.format("fileroot: %s", cfg.fileroot))
    ctx.register("tournament_check_for_trophy", switch_tournament)
    ctx.register("livecpk_make_key", make_key)
    ctx.register("livecpk_get_filepath", get_filepath)
end

return { init = init }
