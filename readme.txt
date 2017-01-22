Sider v3.0 for Pro Evolution Soccer 2017
========================================
Copyright (C) 2017 juce, nesa24



This tool allows you to make small tweaks to your PES experience:

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


debug = 0

- Setting this to 1 will make Sider output some additional information
into the log file (sider.log). This is useful primarily for troubleshooting.
Extra logging may slow the game down, so normally you would want to keep
this setting set to 0. (Defaults to 0: no extra output)


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


CREDITS:
--------
Game research by nesa24 and juce
Sider is written by juce and nesa24
Test content: EPL High-Visibility ball: by -cRoNoS-

