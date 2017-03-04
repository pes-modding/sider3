-- GoalKeeper kit switcher

local team_home
local team_away

local function which_gk_model(filename)
    return string.match(
        filename, ".*(%d+)_[A-Z]+_GK([12])[snrt][tdh]_realUni.bin")
end

local function set_team_id(team_id)
    local id = tonumber(team_id)
    if team_home == nil then
        team_home = id
    elseif team_away == nil then
        if team_home ~= id then
            team_away = id
        end
    end
    return id
end
 
local function make_key(ctx, filename)
    local team_id, gkm = which_gk_model(filename)
    if gkm then
        local id = set_team_id(team_id)
        -- switch away GK to 2nd kit
        if id == team_away then
            return string.gsub(filename, "_GK1st_", "_GK2nd_")
        end
    end
end

local function get_filepath(ctx, filename, key)
    if key then
        log(key)
        return "z:\\cpk-roots\\kits\\" .. key
    end
end

local function reset_teams(ctx, tid)
    log("resetting team ids")
    team_home, team_away = nil, nil
end

local function init(ctx)
    ctx.register("livecpk_make_key", make_key)
    ctx.register("livecpk_get_filepath", get_filepath)
    ctx.register("tournament_check_for_trophy", reset_teams)
end

return { init = init }
