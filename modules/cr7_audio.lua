-- cr7_audio.lua
-- ================
-- Ronaldo unique celebration sound for PES 2017

local m = {}

local cr_sound

function m.make_key(ctx, filename)
    --log(filename)
    if string.match(filename, "common\\demo\\anime\\FoxAnim\\FixDemo\\Animations\\dml_pfm_starjump_f180.gani") then
        if not cr_sound then
            log("Ronaldo celebration loaded: " .. filename)
            -- Play C.Ronaldo "suuu!" sound, when he scores and does his unique celebration
            -- cr_suuu_d6.mp3 has 6 seconds of silence, followed by "suuu!"
            cr_sound = audio.new(ctx.sider_dir .. "content\\audio-demo\\cr_suuu_d6.mp3")
            cr_sound:set_volume(0.4)
            cr_sound:play()
            cr_sound:when_done(function()
                cr_sound = nil
            end)
        end
    end
end

function m.init(ctx)
    ctx.register("livecpk_make_key", m.make_key)
end

return m
