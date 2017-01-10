Sider v2.5 for Pro Evolution Soccer 2017
========================================
Copyright (C) 2017 juce


This tool allows you to make small tweaks to your PES experience:

1. You can freely select sides in competition
modes - where such selection is normally restricted.
For example: in cups, leagues, Champions League, and so for.

2. Extend "Custom" camera sliders beyond 10. 
For "Dynamic Wide" you can enable angle slider.



HOW TO USE:
-----------

Run sider.exe, it will open a small window, which you can
minimize if you want, but do not close it.

Run the game. Make sure you press any keyboard key at least 
once, for example when the game says "Press Any Key". This
is VERY IMPORTANT - to have the operating system map sider.dll
into the running game process.

After that, you can navigate the game with your game controller 
(or keyboard), whichever way you prefer.

If all worked correctly, then on "Select Sides" screens, 
you should be able to move the controllers left and right 
without any restrictions.


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

