-- GoalKeeper kit switcher

local kitroot = ".\\keeper-kits\\"

local function which_gk_model(filename)
    return string.match(
        filename, "(%d+)_[A-Z]+_GK(%d)[snrt][tdh]_realUni.bin")
end

local function make_key(ctx, filename)
    local team_id, gkm = which_gk_model(filename)
    if gkm then
        team_id = tonumber(team_id)
        if team_id == ctx.away_team then
            -- switch away GK to 2nd kit
            return string.gsub(filename, "_GK1st_", "_GK2nd_")
        end
    end
end

local function get_filepath(ctx, filename, key)
    if key then
        log(key)
        return kitroot .. key
    end
end

local function init(ctx)
    ctx.register("livecpk_make_key", make_key)
    ctx.register("livecpk_get_filepath", get_filepath)
end

return { init = init }
