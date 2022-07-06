Sider v3.5 for Pro Evolution Soccer 2017
========================================
Copyright (C) 2017 juce, nesa24



This tool allows you to "enhance" your PES experience:

1. You can freely select sides in competition
modes - where such selection is normally restricted.
For example: in cups, leagues, Champions League, and so for.

2. Extend "Custom" camera sliders beyond 10.
For "Dynamic Wide" you can enable angle slider.

3. "LiveCPK" feature makes it possible to replace game content
at run-time with content from files stored on disk, instead of
having to pack everything into CPK-archives. (This feature
is similar to Kitserver's AFS2FS and to FileLoader for earler
versions of PES).

4. If you feel really adventurous, you can extend Sider functionality
beyond its basic features, by writing extension modules in Lua.
This requires some programming, but it's really not that hard ;-)
See scripting.txt - for detailed documentation on that.



HOW TO USE:
-----------

Run sider.exe, it will open a small window, which you can
minimize if you want, but do not close it.

Run the game. There is no need for any manual trigger action:
Sider should automatically attach to the game process.

If you don't see the effects of Sider in the game, check the
sider.log file (in the same folder where sider.exe is) - it should
contain some helpeful information on what went wrong.


SETTINGS (SIDER.INI)
--------------------

There are several settings you can set in sider.ini:


exe.name = "\PES2017.exe"
exe.name = "\PES2017patched.exe"

- this sets the pattern(s) that the Sider program will use
to identify which of the running processes is the game.
You can have multiple "exe.name" lines in your sider.ini,
which is useful, for example, if you have several exe
files with slightly different names that you use for
online/offline play.


free.select.sides = 1

- enables free movement of controllers. Normally, it is
only possible in Exhibition modes, but with this setting
set to 1, you will be able to move the controllers in the
competition modes too. (0 - disables this feature)


free.first.player = 1

- This allows the 1st controller to be moved into the
middle, disabling it effectively. Use this carefully in the
matches: if you move 1st controller into the middle, make
sure that you have at least one other controller on the left
or on the right. Otherwise, you will lose the control of the
match. (0 - disables this feature)


camera.sliders.max = 50

- This allows to extend the range of camera sliders: Zoom, Height, Angle.
Currently, it only works for "Custom" camera.
The default range is 0-10. (0 - disables this feature)


camea.dynamic-wide.angle.enabled = 1

- This enabled "Angle" slider for "Dynamic Wide" camera.
The feature is somewhat experimental. (0 - disables it)


livecpk.enabled = 1

- Turns on the LiveCPK functionality of Sider. See below for a more
detailed explanation in cpk.root option section.


black.bars.off = 0

- If you set this option to 1, it will turn off the black bars
(letterboxing) at the top and bottom of the screen, or on the left/right,
depending on your playing resolution. NOTE that this only works for the
match itself, and for the main menu. Some of other menu screens and the
edit mode, for example, will still have the black bars, regardless of
this option.
(0 - black bars, 1 - no black bars)


debug = 0

- Setting this to 1 will make Sider output some additional information
into the log file (sider.log). This is useful primarily for troubleshooting.
Extra logging may slow the game down, so normally you would want to keep
this setting set to 0. (Defaults to 0: no extra output)


game.speed = 0.0

- Game speed: -2,1,0,1,2 correspond to in-game settings
But you can also use non-whole numbers and the supported range
is extended to [-15,15]. Example: game.speed = -0.23

If this setting is not specified in sider.ini (commented out or absent),
then the default game behaviour is allowed: game speed is controlled
by the menu slider. However, if you specify the value for "game.speed"
in sider.ini, then this speed is enforced regardless of what the
in-game slider is set to.


close.on.exit = 0

- If this setting is set to 1, then Sider will close itself, when the
game exits. This can be handy, if you use a batch file to start sider
automatically right before the game is launched.
(Defaults to 0: do not close)


start.minimized = 0

- If you set this to 1, then Sider will start with a minimized window.
Again, like the previous option, this setting can be helpful, if you
use a batch file to auto-start sider, just before the game launches.
(Defaults to 0: normal window)


cpk.root = "c:\cpk-roots\balls-root"
cpk.root = "c:\cpk-roots\kits-root"
cpk.root = ".\another-root\stadiums"

- Specifies root folder (or folders), where the game files are stored that
will be used for content replacing at run-time. It works like this:
For example, the game wants to load a file that is stored in some CPK, with
the relative path of "common/render/thumbnail/ball/ball_001.dds". Sider
will intercept that action and check if one of the root folders have this
file. If so, Sider will make the game read the content from that file instead
of using game's original content. If multiple roots are specified, then
they are checked in order that they are listed in sider.ini. As soon as there
is a filename match, the lookup stops. (So, higher root will win, if both of
them have the same file). You can use either absolute paths or relative.
Relative paths will be calculated relative to the folder where sider.exe is
located.


lua.enabled = 1

- This turns on/off the scripting support. Extension modules can be
written in Lua 5.1 (LuaJIT), using a subset of standard libraries and
also objects and events provides by sider. See "scripting.txt" file for
a programmer's guide to writing lua modules for sider.


lua.module = "keeper2nd.lua"
lua.module = "trophy.lua"

- Specifies the order in which the extension modules are loaded. These
modules must be in "modules" folder inside the sider root directory.



CREDITS:
--------
Game research by nesa24 and juce
Sider is written by juce and nesa24
tournaments.txt: ids researched by kilay and other Evo-Web users
Test content:
EPL High-Visibility ball: by -cRoNoS-
EPL Trophy and FA Community Shield: by Ronito
Manchester United GK kits: by G-Style

Sider uses the following 3rd-party software:

LuaJIT by Mike Pall (license-luajit.txt)
miniaudio by David Reid (license-ma.txt)
