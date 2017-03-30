-- Example usage of "memory" library:
-- Find game version information in memory

local m = {}

local pattern =
    "version_dp.bin\x00\x00"

function nullterm(s)
    local finish = s:find("\x00")
    if finish then
        return s:sub(1, finish-1)
    end
    return s
end

function m.init(ctx)
    local addr = memory.search(pattern, 0x400000, 0x4000000)
    if addr then
        -- version should be write after the pattern
        addr = addr + #pattern
        log(string.format("found version info at address: %08x", addr))
        local ver = memory.read(addr, 32)
        ver = nullterm(ver)
        log(string.format("Game version: %s", ver))
    else
        log("Pattern not found. Unknown game version")
    end
end

return m
