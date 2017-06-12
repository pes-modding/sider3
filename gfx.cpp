#define UNICODE

#include "common.h"
#include "imageutil.h"
#include "patterns.h"
#include "gfx.h"
#include "sider.h"

#include <unordered_map>

using namespace std;

typedef int (*getter_t)(lua_State *L, DWORD addr);
typedef int (*setter_t)(lua_State *L, DWORD addr);

void init_gfx_property(
    BYTE *base, IMAGE_SECTION_HEADER *h,
    const char *prop, getter_t get, setter_t set,
    BYTE *pattern, size_t pattern_len, int off, int addr_off=0);

struct handler_t {
    DWORD addr;
    getter_t get;
    setter_t set;
};

typedef unordered_map<string, struct handler_t> gfx_t;
static gfx_t _gfx;

#define MEMOP_BEGIN(a,s) {\
    DWORD old_prot = 0;\
    DWORD new_prot = PAGE_EXECUTE_READWRITE;\
    if (VirtualProtect((BYTE*)(a), s, new_prot, &old_prot)) {

#define MEMOP_END(a,s) \
        VirtualProtect((BYTE*)(a), s, old_prot, NULL);\
    }\
    else {\
        log_(L"PROBLEM: VirtualProtect FAILED at %p\n", (BYTE*)(a));\
    }\
}


static int value_get_double(lua_State *L, DWORD addr)
{
    MEMOP_BEGIN(addr, sizeof(double))
    double v = *(double*)addr;
    lua_pushnumber(L, v);
    MEMOP_END(addr, sizeof(double))
    return 1;
}

static int value_set_double(lua_State *L, DWORD addr)
{
    double v = luaL_checknumber(L, 3);
    MEMOP_BEGIN(addr, sizeof(double))
    *(double*)addr = v;
    MEMOP_END(addr, sizeof(double))
    return 0;
}

static int value_get_float(lua_State *L, DWORD addr)
{
    MEMOP_BEGIN(addr, sizeof(float))
    float v = *(float*)addr;
    lua_pushnumber(L, v);
    MEMOP_END(addr, sizeof(float))
    return 1;
}

static int value_set_float(lua_State *L, DWORD addr)
{
    float v = luaL_checknumber(L, 3);
    MEMOP_BEGIN(addr, sizeof(float))
    *(float*)addr = v;
    MEMOP_END(addr, sizeof(float))
    return 0;
}

static int gfx_get(lua_State *L)
{
    const char *name = luaL_checkstring(L, 2);
    gfx_t::iterator it = _gfx.find(name);
    if (it != _gfx.end()) {
        lua_pop(L, 2);
        return it->second.get(L, it->second.addr);
    }
    logu_("WARN: cannot get unknown property: %s\n", name);
    lua_pop(L, 2);
    lua_pushnil(L);
    return 1;
}

static int gfx_set(lua_State *L)
{
    const char *name = luaL_checkstring(L, 2);
    gfx_t::iterator it = _gfx.find(name);
    if (it != _gfx.end()) {
        int res = it->second.set(L, it->second.addr);
        lua_pop(L, 3);
        return res;
    }
    logu_("WARN: cannot set unknown property: %s\n", name);
    lua_pop(L, 3);
    return 0;
}

static void init_gfx_property(
    BYTE *base, IMAGE_SECTION_HEADER *h,
    const char *prop, getter_t get, setter_t set,
    BYTE *pattern, size_t pattern_len, int off, int addr_off)
{
    BYTE *p;
    DWORD addr;
    struct handler_t ht;
    string name(prop);

    p = find_code_frag(base, h->Misc.VirtualSize, pattern, pattern_len);
    if (!p) {
        logu_("Gfx: (%s) code pattern not matched\n", name.c_str());
    }
    else {
        logu_("Code pattern found at offset: %08x (%08x)\n", (p-base), p);

        addr = *(DWORD*)(p + off);
        ht.addr = addr + addr_off;
        ht.get = get;
        ht.set = set;
        _gfx.insert(pair<string, struct handler_t>(name, ht));
        logu_("Enabling gfx mod: %s ( % p )\n", name.c_str(), addr + addr_off);
    }
}

void lookup_gfx_locations(BYTE *base, IMAGE_SECTION_HEADER *h)
{
    init_gfx_property(base, h,
        "brightness", value_get_float, value_set_float,
        brightness_pattern, sizeof(brightness_pattern)-1,
        brightness_off, brightness_off_off);

    init_gfx_property(base, h,
        "sharpness", value_get_float, value_set_float,
        sharpness_pattern, sizeof(sharpness_pattern)-1,
        sharpness_off, sharpness_off_off);
}

void init_gfx_lib(lua_State *L)
{
    lua_newtable(L);
    lua_newtable(L);
    lua_pushstring(L, "__newindex");
    lua_pushcclosure(L, gfx_set, 0);
    lua_settable(L, -3);
    lua_pushstring(L, "__index");
    lua_pushcclosure(L, gfx_get, 0);
    lua_settable(L, -3);
    lua_setmetatable(L, -2);
    lua_setfield(L, -2, "gfx");
}

