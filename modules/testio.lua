-- testing io library: lets log the source of this module

return {
    init = function(ctx)
        local fname = ctx.sider_dir .. "\\modules\\" .. _FILE
        local f = assert(io.open(fname))
        log(f:read("*all"))
        f:close()
    end
}
