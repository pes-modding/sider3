#ifndef _SIDER_GAMEPLAY_H
#define _SIDER_GAMEPLAY_H

#include "imageutil.h"

#include "lua.hpp"
#include "lauxlib.h"
#include "lualib.h"

void lookup_gameplay_locations(BYTE*, IMAGE_SECTION_HEADER*);
void init_gameplay_lib(lua_State *L);

#endif
