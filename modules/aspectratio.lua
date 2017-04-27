-- set aspect ratio
-- For PES2017.exe 1.04 and 1.04.01 only

local aspect_ratio = 1.4

function init(ctx)
    memory.write(0x1f51c1c, memory.pack("f", aspect_ratio))
    memory.write(0x383f2bf, "\x90\x90\x90\x90\xeb")
end

return { init = init }
