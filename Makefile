# For release builds, use "debug=1" in command line. For instance,
# to build DLLs in release mode: nmake dlls debug=1

CC=cl
LINK=link
RC=rc

!if "$(debug)"=="1"
EXTRA_CFLAGS=/DDEBUG
!else
EXTRA_CFLAGS=/DMYDLL_RELEASE_BUILD
!endif

LPZLIB=soft\zlib123-dll\lib
ZLIBDLL=soft\zlib123-dll\zlib1.dll

# 4731: warning about ebp modification
CFLAGS=/nologo /Od /EHsc /wd4731 $(EXTRA_CFLAGS)
LFLAGS=/NOLOGO
#LIBS=user32.lib gdi32.lib advapi32.lib comctl32.lib shell32.lib shlwapi.lib
LIBS=user32.lib gdi32.lib comctl32.lib version.lib
LIBSDLL=pngdib.obj libpng.a zdll.lib $(LIBS)

LUAINC=/I soft\LuaJIT-2.0.4\src
LUALIBPATH=soft\LuaJIT-2.0.4\src
LUALIB=lua51.lib

all: sider.exe sider.dll

sider.res: sider.rc
	$(RC) -r -fo sider.res sider.rc
sider_main.res: sider_main.rc sider.ico
	$(RC) -r -fo sider_main.res sider_main.rc

common.obj: common.cpp common.h
gameplay.obj: gameplay.cpp gameplay.h patterns.h
imageutil.obj: imageutil.cpp imageutil.h
version.obj: version.cpp

$(LUALIBPATH)\$(LUALIB):
	cd $(LUALIBPATH) && msvcbuild.bat

sider.obj: sider.cpp sider.h patterns.h
sider.dll: sider.obj imageutil.obj version.obj common.obj gameplay.obj sider.res $(LUALIBPATH)\$(LUALIB)
	$(LINK) $(LFLAGS) /out:sider.dll /DLL sider.obj imageutil.obj version.obj common.obj gameplay.obj sider.res /LIBPATH:$(LUALIBPATH) $(LIBS) $(LUALIB)

sider.exe: main.obj sider.dll sider_main.res
	$(LINK) $(LFLAGS) /out:sider.exe main.obj sider_main.res $(LIBS) sider.lib

zlibtool.obj: zlibtool.cpp
zlibtool.exe: zlibtool.obj 
    $(LINK) $(LFLAGS) /out:zlibtool.exe zlibtool.obj /LIBPATH:$(LPZLIB) $(LIBS) zdll.lib

.cpp.obj:
	$(CC) $(CFLAGS) -c $(INC) $(LUAINC) $<

clean:
	del *.obj *.dll *.exp *.res *.lib *.exe *~

clean-all: clean
    cd $(LUALIBPATH) && del /Q lua51.exp lua51.lib lua51.dll luajit.exe

