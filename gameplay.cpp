#define UNICODE

#include "common.h"
#include "imageutil.h"
#include "patterns.h"
#include "gameplay.h"
#include "sider.h"

extern CRITICAL_SECTION _cs;

struct gameplay_t {
    double *shooting_power;
    double *gamespeed;
    double *gamespeed_global;
    double *ball_physics;
    double *ball_weight;
    double *ball_bounce;
    double *ball_friction;
};

static struct gameplay_t _gameplay;

#define MEM_WRITE_BEGIN(a,s) {\
    DWORD old_prot = 0;\
    DWORD new_prot = PAGE_EXECUTE_READWRITE;\
    if (VirtualProtect((BYTE*)(a), s, new_prot, &old_prot)) {

#define MEM_WRITE_END(a,s) \
        VirtualProtect((BYTE*)(a), s, old_prot, NULL);\
    }\
    else {\
        log_(L"VirtualProtect FAILED at %p", (BYTE*)(a));\
    }\
}

static int gameplay_get_ball_weight(lua_State *L)
{
    EnterCriticalSection(&_cs);
    if (_gameplay.ball_weight) {
        double v = *(_gameplay.ball_weight);
        lua_pushnumber(L, v);
    }
    else {
        lua_pushstring(L, "Gameplay ball-weight get is not supported");
        LeaveCriticalSection(&_cs);
        return lua_error(L);
    }
    LeaveCriticalSection(&_cs);
    return 1;
}

static int gameplay_set_ball_weight(lua_State *L)
{
    EnterCriticalSection(&_cs);
    if (_gameplay.ball_weight) {
        if (!lua_isnumber(L, 1)) {
            lua_pushfstring(L, "1st parameter must be a number");
            LeaveCriticalSection(&_cs);
        }
        double v = luaL_checknumber(L, 1);
        MEM_WRITE_BEGIN(_gameplay.ball_weight, sizeof(v))
        *(_gameplay.ball_weight) = v;
        MEM_WRITE_END(_gameplay.ball_weight, sizeof(v))
    }
    else {
        lua_pushstring(L, "Gameplay ball-weight set is not supported");
        LeaveCriticalSection(&_cs);
        return lua_error(L);
    }
    LeaveCriticalSection(&_cs);
    return 0;
}

void lookup_gameplay_locations(BYTE *base, IMAGE_SECTION_HEADER *h)
{
    BYTE *p;

    p = find_code_frag(base, h->Misc.VirtualSize,
        ball_weight_pattern, sizeof(ball_weight_pattern)-1);
    if (!p) {
        log_(L"Gameplay: (ball-weight) code pattern not matched\n");
    }
    else {
        log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
        log_(L"Enabling ball-weight modification\n");
        _gameplay.ball_weight = *(double**)(p + ball_weight_off);
    }
}

void init_gameplay_lib(lua_State *L)
{
    lua_newtable(L);
    lua_pushstring(L, "set_ball_weight");
    lua_pushcclosure(L, gameplay_set_ball_weight, 0);
    lua_settable(L, -3);
    lua_pushstring(L, "get_ball_weight");
    lua_pushcclosure(L, gameplay_get_ball_weight, 0);
    lua_settable(L, -3);
    lua_setfield(L, -2, "gameplay");
}

