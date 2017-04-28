-- set aspect ratio
-- For PES2017.exe 1.04 and 1.04.01 only

local aspect_ratio = 1.6

function init(ctx)
    memory.write(0x1f51c1c, memory.pack("f", aspect_ratio))
    memory.write(0x383f2bf, "\xeb\x5b\x90\x90")
end

return { init = init }
