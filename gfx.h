#ifndef _SIDER_GFX_H
#define _SIDER_GFX_H

#include "imageutil.h"

#include "lua.hpp"
#include "lauxlib.h"
#include "lualib.h"

void lookup_gfx_locations(BYTE*, IMAGE_SECTION_HEADER*);
void init_gfx_lib(lua_State *L);

#endif
