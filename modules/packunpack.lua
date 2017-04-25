-- testing module for memory.pack and memory.unpack

local tests = {
    { "f", '\x66\xe6\xf6\x42', 123.45, 0.00001 },
    { "d", '\xcd\xcc\xcc\xcc\xcc\xdc\x5e\x40', 123.45, 0.00000001 },
    { "i", '\x87\xd6\x12\x00', 1234567, 0, },
    { "s", '\x39\x30', 12345, 0, },
    { "ui",'\x00\x5e\xd0\xb2', 3000000000, 0, },
    { "us",'\x69\xa5', 42345, 0, },
}

function hex(s)
    return string.gsub(s, ".", function(c)
        return string.format("%02x ", string.byte(c))
    end)
end

function init(ctx)
    for _,t in ipairs(tests) do
        local fmt, s, v, err = t[1], t[2], t[3], t[4]
        local packed = memory.pack(fmt, v)
        local unpacked = memory.unpack(fmt, packed)
        log(string.format("%s vs %s", hex(s), hex(packed)))
        assert(s == packed)
        log(string.format("%s vs %s", v, unpacked))
        assert(err >= math.abs(v - unpacked))
    end
end

return { init = init }
