-- Another GoalKeeper kit switcher: using rewrite

local function which_gk_model(filename)
    return string.match(
        filename, "(%d+)_[A-Z]+_GK(%d)[snrt][tdh]_realUni%.bin")
end

local function rewrite(ctx, filename)
    local team_id, gkm = which_gk_model(filename)
    if gkm then
        team_id = tonumber(team_id)
        if team_id == ctx.away_team then
            -- switch away GK to 2nd kit
            return string.gsub(filename, "_GK1st_", "_GK2nd_")
        end
    end
end

local function init(ctx)
    ctx.register("livecpk_rewrite", rewrite)
end

return { init = init }
