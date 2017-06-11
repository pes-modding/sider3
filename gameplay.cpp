#define UNICODE

#include "common.h"
#include "imageutil.h"
#include "patterns.h"
#include "gameplay.h"
#include "sider.h"

#include <unordered_map>

using namespace std;

typedef int (*getter_t)(lua_State *L, DWORD addr);
typedef int (*setter_t)(lua_State *L, DWORD addr);

struct handler_t {
    DWORD addr;
    getter_t get;
    setter_t set;
};

typedef unordered_map<string, struct handler_t> gameplay_t;
static gameplay_t _gameplay;

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

static int gameplay_get(lua_State *L)
{
    const char *name = luaL_checkstring(L, 2);
    gameplay_t::iterator it = _gameplay.find(name);
    if (it != _gameplay.end()) {
        lua_pop(L, 2);
        return it->second.get(L, it->second.addr);
    }
    logu_("WARN: cannot get unknown property: %s\n", name);
    lua_pop(L, 2);
    lua_pushnil(L);
    return 1;
}

static int gameplay_set(lua_State *L)
{
    const char *name = luaL_checkstring(L, 2);
    gameplay_t::iterator it = _gameplay.find(name);
    if (it != _gameplay.end()) {
        int res = it->second.set(L, it->second.addr);
        lua_pop(L, 3);
        return res;
    }
    logu_("WARN: cannot set unknown property: %s\n", name);
    lua_pop(L, 3);
    return 0;
}

static void init_gameplay_property(
    BYTE *base, IMAGE_SECTION_HEADER *h,
    const char *prop, getter_t get, setter_t set,
    BYTE *pattern, size_t pattern_len, int off)
{
    BYTE *p;
    DWORD addr;
    struct handler_t ht;
    string name(prop);

    p = find_code_frag(base, h->Misc.VirtualSize, pattern, pattern_len);
    if (!p) {
        logu_("Gameplay: (%s) code pattern not matched\n", name.c_str());
    }
    else {
        logu_("Code pattern found at offset: %08x (%08x)\n", (p-base), p);

        addr = *(DWORD*)(p + off);
        ht.addr = addr;
        ht.get = get;
        ht.set = set;
        _gameplay.insert(pair<string, struct handler_t>(name, ht));
        logu_("Enabling gameplay mod: %s ( % p )\n", name.c_str(), addr);
    }
}

void lookup_gameplay_locations(BYTE *base, IMAGE_SECTION_HEADER *h)
{
    init_gameplay_property(base, h,
        "ball_physics", value_get_double, value_set_double,
        ball_physics_pattern, sizeof(ball_physics_pattern)-1,
        ball_physics_off);

    init_gameplay_property(base, h,
        "ball_bounce", value_get_double, value_set_double,
        ball_physics_pattern, sizeof(ball_physics_pattern)-1,
        ball_bounce_off);

    init_gameplay_property(base, h,
        "ball_weight", value_get_double, value_set_double,
        ball_weight_pattern, sizeof(ball_weight_pattern)-1,
        ball_weight_off);

    init_gameplay_property(base, h,
        "ball_friction", value_get_double, value_set_double,
        ball_friction_pattern, sizeof(ball_friction_pattern)-1,
        ball_friction_off);

    init_gameplay_property(base, h,
        "ball_magnus", value_get_double, value_set_double,
        ball_magnus_pattern, sizeof(ball_magnus_pattern)-1,
        ball_magnus_off);

    init_gameplay_property(base, h,
        "shooting_power", value_get_double, value_set_double,
        shot_power_pattern, sizeof(shot_power_pattern)-1,
        shot_power_off);

    init_gameplay_property(base, h,
        "speed_global", value_get_double, value_set_double,
        speed_global_pattern, sizeof(speed_global_pattern)-1,
        speed_global_off);

    init_gameplay_property(base, h,
        "speed", value_get_double, value_set_double,
        speed_pattern, sizeof(speed_pattern)-1,
        speed_off);
}

void init_gameplay_lib(lua_State *L)
{
    lua_newtable(L);
    lua_newtable(L);
    lua_pushstring(L, "__newindex");
    lua_pushcclosure(L, gameplay_set, 0);
    lua_settable(L, -3);
    lua_pushstring(L, "__index");
    lua_pushcclosure(L, gameplay_get, 0);
    lua_settable(L, -3);
    lua_setmetatable(L, -2);
    lua_setfield(L, -2, "gameplay");
}

