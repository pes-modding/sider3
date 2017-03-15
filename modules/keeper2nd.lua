-- GoalKeeper kit switcher

local kitroot = ".\\content\\keeper-kits\\"

local function which_gk_model(filename)
    return string.match(
        filename, "(%d+)_[A-Z]+_GK(%d)[snrt][tdh]_realUni%.bin")
end

local function which_gk_tex(filename)
    return string.match(
        filename, "uniform.texture.[cu](%d+)g(%d)")
end

local function make_key(ctx, filename)
    local team_id, gkm = which_gk_model(filename)
    if gkm then
        team_id = tonumber(team_id)
        if team_id == ctx.away_team then
            -- switch away GK to 2nd kit
            return string.gsub(filename, "_GK1st_", "_GK2nd_")
        end
    else
        local team_id, gkt = which_gk_tex(filename)
        if gkt then
            team_id = tonumber(team_id)
            if team_id == ctx.away_team then
                -- return filename as is.
                -- This is needed so that we serve the texture
                -- file from our own root.
                return filename
            end
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
    if kitroot:sub(1,1)=='.' then
        kitroot = ctx.sider_dir .. kitroot
    end
    ctx.register("livecpk_make_key", make_key)
    ctx.register("livecpk_get_filepath", get_filepath)
end

return { init = init }
