#define UNICODE

//#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <list>
#include <string>
#include <unordered_map>
#include "imageutil.h"
#include "sider.h"
#include "utf8.h"

#include "lua.hpp"
#include "lauxlib.h"
#include "lualib.h"

#ifndef LUA_OK
#define LUA_OK 0
#endif

#define DBG if (_config->_debug)

using namespace std;

lua_State *L = NULL;
CRITICAL_SECTION _cs;

static DWORD get_target_addr(DWORD call_location);
static void hook_call_point(DWORD addr, void* func, int codeShift, int numNops, bool addRetn=false);

void lcpk_lookup_file_cp();
void lcpk_get_file_info_cp();
void lcpk_before_read_cp();

void trophy_map_cp();

void team_ids_read_cp();
void team_info_write_cp();

void minutes_set_cp();
void set_defaults_cp();
void write_exhib_id_cp();
void write_tournament_id_cp();

// locations to fill, when hooking
DWORD _tid_addr1 = 0;
DWORD _tid_target1 = 0;
DWORD _tid_target2 = 0;

int convert_tournament_id2();
int convert_tournament_id(int id);

int _curr_tournament_id(0);
bool _replace_trophy(false);

BOOL WINAPI lcpk_at_read_file(
    _In_        HANDLE       hFile,
    _Out_       LPVOID       lpBuffer,
    _In_        DWORD        nNumberOfBytesToRead,
    _Out_opt_   LPDWORD      lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped);

DWORD WINAPI lcpk_at_set_file_pointer(
    _In_        HANDLE hFile,
    _In_        LONG   lDistanceToMove,
    _Inout_opt_ PLONG  lpDistanceToMoveHigh,
    _In_        DWORD  dwMoveMethod);

static DWORD dwThreadId;
static DWORD hookingThreadId = 0;
static HMODULE myHDLL;
static HHOOK handle;

void set_context_field_int(const char *name, int value);

bool trophy_server_make_key(char *file_name, char *key);
wstring *trophy_server_get_filepath(char *file_name, char *key);

typedef unordered_map<string,wstring*> lookup_cache_t;
lookup_cache_t _lookup_cache;

struct module_t {
    lookup_cache_t *cache;
    lua_State* L;
    int evt_trophy_check;
    int evt_lcpk_make_key;
    int evt_lcpk_get_filepath;
    int evt_lcpk_rewrite;
    int evt_set_home_team;
    int evt_set_away_team;
    int evt_set_tid;
    int evt_set_match_time;
};
list<module_t*> _modules;
module_t* _curr_m;

wchar_t module_filename[MAX_PATH];
wchar_t dll_log[MAX_PATH];
wchar_t dll_ini[MAX_PATH];
wchar_t sider_dir[MAX_PATH];

struct CPK_INFO {
    DWORD dw0[8];
    DWORD dw1;
    char *cpk_filename;
    DWORD dw2[6];
};

struct FILE_INFO {
    DWORD size;
    DWORD size2;
    DWORD offset;
    DWORD zero;
    char filename[0x200];
};

struct FILE_HANDLE_INFO {
    DWORD handle;
    DWORD zero1;
    DWORD size;
    DWORD zero2;
    DWORD currentOffset;
    DWORD zero3;
    DWORD padding[4];
};

struct READ_STRUCT {
    DWORD dw0;
    FILE_HANDLE_INFO *fileHandleInfo;
    DWORD dw1[8];
    DWORD cpkFileSize;
    DWORD dw2[5];
    DWORD offset;
    DWORD dw3[3];
    DWORD sizeRead;
    DWORD bufferOffset;
    DWORD bufferOffset2;
    DWORD dw4;
    DWORD size;
    BYTE *buffer;
    BYTE *buffer2;
    DWORD dw5[0x94/4];
    DWORD orgOffset;
    DWORD dw6;
    DWORD totalSize;
    DWORD dw7;
    FILE_HANDLE_INFO *fileHandleInfo2;
    DWORD dw8[9];
    char filename[0x80];
};

struct READ_REPL {
    DWORD replaceFlag;
    BYTE *realBuffer;
    DWORD realOffset;
    READ_STRUCT *rs;
    HANDLE handle;
};

// original call destination of "lookup_file"
static DWORD _lookup_file_org = 0;

// original call destination of "before_read"
static DWORD _before_read_org = 0;

// original call destination of "team_ids_read"
static DWORD _team_ids_read_org = 0;

// original call destination of "team_info_write"
static DWORD _team_info_write_org = 0;

bool _is_game(false);
bool _is_sider(false);
HANDLE _mh = NULL;

// livecpk patterns
BYTE lcpk_pattern_get_buffer_size[16] = 
    "\x8b\x8d\xc0\xff\xff\xff"
    "\x8b\x85\xbc\xff\xff\xff"
    "\x83\xc4\x0c";
BYTE lcpk_pattern_create_buffer[15] =
    "\x89\x46\x38"
    "\x39\x5e\x38"
    "\x0f\x84\xee\x00\x00\x00"
    "\x6a\x01";
BYTE lcpk_pattern_after_read[18] =
    "\xc7\x46\x10\x01\x00\x00\x00"
    "\x83\x7e\x10\x01"
    "\x0f\x85\xbb\x00\x00\x00";
BYTE lcpk_pattern_lookup_file[17] =
    "\xeb\x6c"
    "\x8d\x85\xac\xfd\xff\xff"
    "\x50"
    "\x8d\x85\xb0\xfd\xff\xff"
    "\x50";
int lcpk_offs_lookup_file = -5;

BYTE lcpk_pattern_get_file_info[12] = 
    "\x83\x67\x14\x00"
    "\x83\x67\x1c\x00"
    "\x89\x4f\x04";

BYTE lcpk_pattern_before_read[10] =
    "\x89\x46\x18"
    "\xc6\x46\x6c\x01"
    "\x31\xc0";
int lcpk_offs_before_read = -12;

BYTE lcpk_pattern_at_read_file[14] =
    "\x56"
    "\x8d\x45\x08"
    "\x50"
    "\x53"
    "\xff\x75\x1c"
    "\xff\x37"
    "\xff\x15";
int lcpk_offs_at_read_file = 11;

BYTE lcpk_pattern_at_set_file_pointer[23] =
    "\xff\x75\x14"
    "\x89\x85\xfc\xff\xff\xff"
    "\x8d\x85\xfc\xff\xff\xff"
    "\x50"
    "\xff\x75\x0c"
    "\xff\x75\x08";
int lcpk_offs_at_set_file_pointer = 22;

// more patterns
BYTE bb_pattern[13] =
    "\x80\x7e\x0c\x00"
    "\x75\x06"
    "\x80\x7e\x0d\x00"
    "\x74\x09";
int bb_offs = 4;

BYTE trophy_pattern[11] =
    "\x56"
    "\x89\xce"
    "\x50"
    "\x89\x86\x08\x2c\x00\x00";
int trophy_offs = 4;

// team ids
BYTE team_ids_pattern1[14] =
    "\x81\xe2\xff\x3f\x00\x00"
    "\x31\x94\xb5\xc8\xff\xff\xff";
int team_ids_off1 = 0x38;

BYTE team_ids_pattern2[18] =
    "\x81\xc7\x48\x02\x00\x00"
    "\xb9\x0b\x00\x00\x00"
    "\x8d\xb5\xa0\xff\xff\xff";
int team_ids_off2 = 0x22;

/*
BYTE team_ids_pattern2[] =
    "\x66\x89\x86\xf8\x01\x00\x00"
    "\x89\x8e\xfc\x01\x00\x00"
    "\x66\x89\x53\x2c";
int team_ids_off2 = -8;
*/

// number of minutes
BYTE minutes_pattern[14] =
    "\x55"
    "\x89\xe5"
    "\x8a\x45\x08"
    "\x88\x41\x14"
    "\x5d"
    "\xc2\x04\x00";
int minutes_off = 3;

// set default settings
BYTE settings_pattern[16] =
    "\xc7\x06\xff\xff\xff\xff"
    "\xc7\x46\x08\x37\x00\x00\x00"
    "\x88\x5e";
int settings_off = 0;

// write tournament id
BYTE write_tid_pattern[18] =
    "\x8b\x7d\x08"
    "\x66\x8b\x07"
    "\x66\x89\x06"
    "\x66\x8b\x4f\x02"
    "\x66\x89\x4e\x02";
int write_tid_off = 17;

// write exhib id
BYTE write_exhib_id_pattern[14] =
    "\xc7\x46\x50\x02\x00\x00\x00"
    "\x5e"
    "\xc3"
    "\x8b\x46\x4c"
    "\x50";
int write_exhib_id_off = 0x22;

// tid function pattern
BYTE tid_func_pattern[12] =
    "\x83\xc0\xda"
    "\x83\xc4\x04"
    "\x83\xf8\x3f"
    "\x77\x14";
int tid_func_off1 = -5;
int tid_func_off2 = -0x1c;

bool patched(false);
bool patched2(false);
bool patched3(false);
BYTE *place(NULL);
BYTE *place2(NULL);
BYTE *cam_places[3];
BYTE *cam_dynamic_wide_places[3];

BYTE org_code[5];
BYTE org_code2[6];
BYTE code_follows[10] = 
    "\x8b\x5d\x0c"  // mov ebx, dword ptr ss:[ebp+0c]
    "\x3b\x5d\x10"  // cmp ebx, dword ptr ss:[ebp+10]
    "\x8b\x75\x08"; // mov esi, dword ptr ss:[ebp+08]
BYTE code_free_first[4] = 
    "\x0f\x94\xd0"; // sete al

BYTE org_cut_scenes[6];
BYTE cut_scenes_code[] =
    "\xc7\x06\x30\x00\x01\x00"; // mov dword ptr ds:[esi],10030

BYTE cam_sliders_code_pat1[10] =
    //"\x74\x66"
    //"\x4e"
    //"\x74\x1a"
    //"\x4e"
    //"\x74\x0d"
    //"\x4e";
    "\x4f"
    "\x74\x20"
    "\x4f"
    "\x74\x10"
    "\x4f"
    "\x75\x41";

BYTE cam_sliders_code_off1 = 0x2f; //0x28;

BYTE cam_sliders_code_pat2[14] = //[8] =
    //"\x8b\x45\xcc"
    //"\x8b\x4d\xd0"
    //"\x50";
    "\x8b\x85\xcc\xff\xff\xff"
    "\x8b\x8d\xd0\xff\xff\xff"
    "\x50";
BYTE cam_sliders_code_off2 = 0x19; //0x13;

BYTE cam_sliders_code_pat3[9] =
    "\x4f"
    "\x74\x18"
    "\x4f"
    "\x74\x0c"
    "\x4f"
    "\x75";
BYTE cam_sliders_code_off3 = 0x23;

BYTE cam_dynamic_wide_pat1[9] = //[13] = 
    //"\xd9\x5d\xb8"
    //"\xd9\x86\xb0\x00\x00\x00"
    //"\xd9\x45\xe0";
    "\xeb\x77"
    "\xd9\x85\xe8\xff\xff\xff";
BYTE cam_dynamic_wide_off1 = 1; //0x1e;
BYTE cam_dynamic_wide_patch1[2] = "\x30";
BYTE cam_dynamic_wide_org1[2];
BYTE cam_dynamic_wide_off2 = 0x6a; //0x54;
BYTE cam_dynamic_wide_patch2[3] = "\x90\x90";
BYTE cam_dynamic_wide_org2[3];

BYTE cam_dynamic_wide_pat3[9] =
    "\x80\xfa\x04"
    "\x77\x25" //"\x77\x1f"
    "\x0f\xb6\xc2";
BYTE cam_dynamic_wide_off3 = 2;
BYTE cam_dynamic_wide_patch3[2] = "\x06";
BYTE cam_dynamic_wide_org3[2];


static void string_strip_quotes(wstring& s)
{
    static const wchar_t* chars = L" \t\n\r\"'";
    int e = s.find_last_not_of(chars);
    s.erase(e + 1);
    int b = s.find_first_not_of(chars);
    s.erase(0,b);
}

class config_t {
public:
    bool _debug;
    bool _livecpk_enabled;
    bool _lookup_cache_enabled;
    bool _lua_enabled;
    bool _luajit_extensions_enabled;
    list<wstring> _lua_extra_globals;
    int _dll_mapping_option;
    wstring _section_name;
    list<wstring> _code_sections;
    list<wstring> _cpk_roots;
    list<wstring> _exe_names;
    list<wstring> _module_names;
    bool _free_select_sides;
    bool _free_first_player;
    bool _cut_scenes;
    int _camera_sliders_max;
    bool _camera_dynamic_wide_angle_enabled;
    bool _black_bars_off;
    DWORD _hp_lookup_file;
    DWORD _hp_get_file_info;
    DWORD _hp_before_read;
    DWORD _hp_at_read_file;
    DWORD _hp_at_set_file_pointer;

    config_t(const wstring& section_name, const wchar_t* config_ini) : 
                 _section_name(section_name),
                 _debug(false),
                 _livecpk_enabled(false),
                 _lookup_cache_enabled(true),
                 _lua_enabled(true),
                 _luajit_extensions_enabled(false),
                 _dll_mapping_option(0),
                 _free_select_sides(false),
                 _free_first_player(false),
                 _cut_scenes(false),
                 _camera_sliders_max(0),
                 _camera_dynamic_wide_angle_enabled(false),
                 _black_bars_off(false),
                 _hp_lookup_file(0),
                 _hp_get_file_info(0),
                 _hp_before_read(0),
                 _hp_at_read_file(0),
                 _hp_at_set_file_pointer(0)
    {
        wchar_t settings[32767];
        RtlZeroMemory(settings, sizeof(settings));
        GetPrivateProfileSection(_section_name.c_str(),
            settings, sizeof(settings)/sizeof(wchar_t), config_ini);

        wchar_t* p = settings;
        while (*p) {
            wstring pair(p);
            wstring key(pair.substr(0, pair.find(L"=")));
            wstring value(pair.substr(pair.find(L"=")+1));
            string_strip_quotes(value);

            if (wcscmp(L"exe.name", key.c_str())==0) {
                _exe_names.push_back(value);
            }
            else if (wcscmp(L"code.section", key.c_str())==0) {
                _code_sections.push_back(value);
            }
            else if (wcscmp(L"lua.module", key.c_str())==0) {
                _module_names.push_back(value);
            }
            else if (wcscmp(L"lua.extra-globals", key.c_str())==0) {
                bool done(false);
                int start = 0, end = 0;
                while (!done) {
                    end = value.find(L",", start);
                    done = (end == string::npos);

                    wstring name((done) ?
                        value.substr(start) :
                        value.substr(start, end - start));
                    string_strip_quotes(name);
                    if (!name.empty()) {
                        _lua_extra_globals.push_back(name);
                    }
                    start = end + 1;
                }
            }
            else if (wcscmp(L"cpk.root", key.c_str())==0) {
                if (value[value.size()-1] != L'\\') {
                    value += L'\\';
                }
                // handle relative roots
                if (value[0]==L'.') {
                    wstring rel(value);
                    value = sider_dir;
                    value += rel;
                }
                _cpk_roots.push_back(value);
            }

            p += wcslen(p) + 1;
        }

        _debug = GetPrivateProfileInt(_section_name.c_str(),
            L"debug", _debug,
            config_ini);
        
        _livecpk_enabled = GetPrivateProfileInt(_section_name.c_str(),
            L"livecpk.enabled", _livecpk_enabled,
            config_ini);
        
        _lookup_cache_enabled = GetPrivateProfileInt(_section_name.c_str(),
            L"lookup-cache.enabled", _lookup_cache_enabled,
            config_ini);

        _lua_enabled = GetPrivateProfileInt(_section_name.c_str(),
            L"lua.enabled", _lua_enabled,
            config_ini);
        
        _luajit_extensions_enabled = GetPrivateProfileInt(_section_name.c_str(),
            L"luajit.ext.enabled", _luajit_extensions_enabled,
            config_ini);
        
        _dll_mapping_option = GetPrivateProfileInt(_section_name.c_str(),
            L"dll-mapping.option", _dll_mapping_option,
            config_ini);
        
        _free_select_sides = GetPrivateProfileInt(_section_name.c_str(),
            L"free.select.sides", _free_select_sides,
            config_ini);

        _free_first_player = GetPrivateProfileInt(_section_name.c_str(),
            L"free.first.player", _free_first_player,
            config_ini);

        _black_bars_off = GetPrivateProfileInt(_section_name.c_str(),
            L"black.bars.off", _black_bars_off,
            config_ini);

        //_cut_scenes = GetPrivateProfileInt(_section_name.c_str(),
        //    L"cut.scenes", _cut_scenes,
        //    config_ini);

        _camera_sliders_max = GetPrivateProfileInt(_section_name.c_str(),
            L"camera.sliders.max", _camera_sliders_max,
            config_ini);

        if (_camera_sliders_max != 0) {
            if (_camera_sliders_max < 1) {
                _camera_sliders_max = 10;
            }
            else if (_camera_sliders_max > 127) {
                _camera_sliders_max = 127;
            }
        }

        _camera_dynamic_wide_angle_enabled = GetPrivateProfileInt(
            _section_name.c_str(),
            L"camera.dynamic-wide.angle.enabled", 
            _camera_dynamic_wide_angle_enabled,
            config_ini);

    }
};

config_t* _config;

bool init_paths() {
    wchar_t *p;

    // prep log filename
    memset(dll_log, 0, sizeof(dll_log));
    if (GetModuleFileName(myHDLL, dll_log, MAX_PATH)==0) {
        return FALSE;
    }
    p = wcsrchr(dll_log, L'.');
    wcscpy(p, L".log");

    // prep ini filename
    memset(dll_ini, 0, sizeof(dll_ini));
    wcscpy(dll_ini, dll_log);
    p = wcsrchr(dll_ini, L'.');
    wcscpy(p, L".ini");

    // prep sider dir
    memset(sider_dir, 0, sizeof(sider_dir));
    wcscpy(sider_dir, dll_log);
    p = wcsrchr(sider_dir, L'\\');
    *(p+1) = L'\0';

    return true;
}

__declspec(dllexport) void log_(const wchar_t *format, ...)
{
    FILE *file = _wfopen(dll_log, L"a+, ccs=UTF-8");
    if (file) {
        va_list params;
        va_start(params, format);
        vfwprintf(file, format, params);
        va_end(params);
        fclose(file);
    }
}

__declspec(dllexport) void logu_(const char *format, ...)
{
    FILE *file = _wfopen(dll_log, L"a+");
    if (file) {
        va_list params;
        va_start(params, format);
        vfprintf(file, format, params);
        va_end(params);
        fclose(file);
    }
}

__declspec(dllexport) void start_log_(const wchar_t *format, ...)
{
    FILE *file = _wfopen(dll_log, L"wt, ccs=UTF-8");
    if (file) {
        va_list params;
        va_start(params, format);
        vfwprintf(file, format, params);
        va_end(params);
        fclose(file);
    }
}

static int sider_log(lua_State *L) {
    const char *s = luaL_checkstring(L, -1);
    lua_getfield(L, lua_upvalueindex(1), "_FILE");
    const char *fname = lua_tostring(L, -1);
    logu_("[%s] %s\n", fname, s);
    lua_pop(L, 2);
    return 0;
}

void read_configuration(config_t*& config)
{
    wchar_t names[1024];
    size_t names_len = sizeof(names)/sizeof(wchar_t);
    GetPrivateProfileSectionNames(names, names_len, dll_ini);

    wchar_t *p = names;
    while (p && *p) {
        wstring name(p);
        if (name == L"sider") {
            config = new config_t(name, dll_ini);
            break;
        }
        p += wcslen(p) + 1;
    }
}

static bool skip_process(wchar_t* name)
{
    wchar_t *filename = wcsrchr(name, L'\\');
    if (filename) {
        if (wcsicmp(filename, L"\\explorer.exe") == 0) {
            return true;
        }
        if (wcsicmp(filename, L"\\steam.exe") == 0) {
            return true;
        }
        if (wcsicmp(filename, L"\\steamwebhelper.exe") == 0) {
            return true;
        }
    }
    return false;
}

static bool is_sider(wchar_t* name)
{
    wchar_t *filename = wcsrchr(name, L'\\');
    if (filename) {
        if (wcsicmp(filename, L"\\sider.exe") == 0) {
            return true;
        }
    }
    return false;
}

static bool write_mapping_info(config_t *config)
{
    // determine the size needed
    DWORD size = sizeof(wchar_t);
    list<wstring>::iterator it;
    for (it = _config->_exe_names.begin();
            it != _config->_exe_names.end();
            it++) {
        size += sizeof(wchar_t) * (it->size() + 1);
    }

    _mh = CreateFileMapping(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT,
        0, size, SIDER_FM);
    if (!_mh) {
        log_(L"W: CreateFileMapping FAILED: %d\n", GetLastError());
        return false;
    }
    wchar_t *mem = (wchar_t*)MapViewOfFile(_mh, FILE_MAP_WRITE, 0, 0, 0);
    if (!mem) {
        log_(L"W: MapViewOfFile FAILED: %d\n", GetLastError());
        CloseHandle(_mh);
        return false;
    }

    memset(mem, 0, size);
    for (it = config->_exe_names.begin();
            it != _config->_exe_names.end();
            it++) {
        wcscpy(mem, it->c_str());
        mem += it->size() + 1;
    }
    return true;
}

static bool is_pes(wchar_t* name, wstring** match)
{
    HANDLE h = OpenFileMapping(FILE_MAP_READ, FALSE, SIDER_FM);
    if (!h) {
        int err = GetLastError();
        wchar_t *t = new wchar_t[MAX_PATH];
        GetModuleFileName(NULL, t, MAX_PATH);
        log_(L"R: OpenFileMapping FAILED (for %s): %d\n", t, err);
        delete t;
        return false;
    }
    BYTE *patterns = (BYTE*)MapViewOfFile(h, FILE_MAP_READ, 0, 0, 0);
    if (!patterns) {
        int err= GetLastError();
        wchar_t *t = new wchar_t[MAX_PATH];
        GetModuleFileName(NULL, t, MAX_PATH);
        log_(L"R: MapViewOfFile FAILED (for %s): %d\n", t, err);
        delete t;
        CloseHandle(h);
        return false;
    }

    bool result = false;
    wchar_t *filename = wcsrchr(name, L'\\');
    if (filename) {
        wchar_t *s = (wchar_t*)patterns;
        while (*s != L'\0') {
            if (wcsicmp(filename, s) == 0) {
                *match = new wstring(s);
                result = true;
                break;
            }
            s = s + wcslen(s) + 1;
        }
    }
    UnmapViewOfFile(h);
    CloseHandle(h);
    return result;
}

static DWORD get_target_addr(DWORD call_location)
{
    if (call_location) {
        BYTE* bptr = (BYTE*)call_location;
        DWORD protection = 0;
        DWORD newProtection = PAGE_EXECUTE_READWRITE;
        if (VirtualProtect(bptr, 8, newProtection, &protection)) {
            // get original target
            DWORD* ptr = (DWORD*)(call_location + 1);
            return (DWORD)(ptr[0] + call_location + 5);
        }
    }
    return 0;
}

static void hook_call_point(DWORD addr, void* func, int codeShift, int numNops, bool addRetn)
{
    DWORD target = (DWORD)func + codeShift;
	if (addr && target)
	{
	    BYTE* bptr = (BYTE*)addr;
	    DWORD protection = 0;
	    DWORD newProtection = PAGE_EXECUTE_READWRITE;
	    if (VirtualProtect(bptr, 16, newProtection, &protection)) {
	        bptr[0] = 0xe8;
	        DWORD* ptr = (DWORD*)(addr + 1);
	        ptr[0] = target - (DWORD)(addr + 5);
            // padding with NOPs
            for (int i=0; i<numNops; i++) bptr[5+i] = 0x90;
            if (addRetn)
                bptr[5+numNops]=0xc3;
	        log_(L"Function (%08x) HOOKED at address (%08x)\n", target, addr);
	    }
	}
}

BYTE* find_code(BYTE *base, DWORD max_offset)
{
    BYTE *p = base;
    BYTE *max_p = base + max_offset;
    while (p < max_p && memcmp(p, code_follows, 9)!=0) {
        p += 1;
    }
    if (p < max_p) {
        return p;
    }
    return NULL;
}

BYTE* find_free_first(BYTE *base, DWORD max_offset)
{
    BYTE *p = base;
    BYTE *max_p = base + max_offset;
    while (p < max_p && memcmp(p, code_free_first, 3)!=0) {
        p += 1;
    }
    if (p < max_p) {
        return p;
    }
    return NULL;
}

BYTE* find_cut_scenes(BYTE *base, DWORD max_offset)
{
    BYTE *p = base;
    BYTE *max_p = base + max_offset;
    while (p < max_p && memcmp(p, cut_scenes_code, 6)!=0) {
        p += 1;
    }
    if (p < max_p) {
        return p;
    }
    return NULL;
}

BYTE* find_code_frag(BYTE *base, DWORD max_offset, BYTE *frag, size_t frag_len)
{
    BYTE *p = base;
    BYTE *max_p = base + max_offset;
    while (p < max_p && memcmp(p, frag, frag_len)!=0) {
        p += 1;
    }
    if (p < max_p) {
        return p;
    }
    return NULL;

}

static int sider_context_register(lua_State *L)
{
    const char *event_key = luaL_checkstring(L, 1);
    if (!lua_isfunction(L, 2)) {
        lua_pushstring(L, "second argument must be a function");
        return lua_error(L);
    }
    if (strcmp(event_key, "tournament_check_for_trophy")==0) {
        lua_pushvalue(L, -1);
        lua_xmove(L, _curr_m->L, 1);
        _curr_m->evt_trophy_check = lua_gettop(_curr_m->L);
        logu_("Registered for \"%s\" event\n", event_key);
    }
    else if (strcmp(event_key, "livecpk_make_key")==0) {
        lua_pushvalue(L, -1);
        lua_xmove(L, _curr_m->L, 1);
        _curr_m->evt_lcpk_make_key = lua_gettop(_curr_m->L);
        logu_("Registered for \"%s\" event\n", event_key);
    }
    else if (strcmp(event_key, "livecpk_get_filepath")==0) {
        lua_pushvalue(L, -1);
        lua_xmove(L, _curr_m->L, 1);
        _curr_m->evt_lcpk_get_filepath = lua_gettop(_curr_m->L);
        logu_("Registered for \"%s\" event\n", event_key);
    }
    else if (strcmp(event_key, "livecpk_rewrite")==0) {
        lua_pushvalue(L, -1);
        lua_xmove(L, _curr_m->L, 1);
        _curr_m->evt_lcpk_rewrite = lua_gettop(_curr_m->L);
        logu_("Registered for \"%s\" event\n", event_key);
    }
    else if (strcmp(event_key, "set_home_team")==0) {
        lua_pushvalue(L, -1);
        lua_xmove(L, _curr_m->L, 1);
        _curr_m->evt_set_home_team = lua_gettop(_curr_m->L);
        logu_("Registered for \"%s\" event\n", event_key);
    }
    else if (strcmp(event_key, "set_away_team")==0) {
        lua_pushvalue(L, -1);
        lua_xmove(L, _curr_m->L, 1);
        _curr_m->evt_set_away_team = lua_gettop(_curr_m->L);
        logu_("Registered for \"%s\" event\n", event_key);
    }
    else if (strcmp(event_key, "set_tournament_id")==0) {
        lua_pushvalue(L, -1);
        lua_xmove(L, _curr_m->L, 1);
        _curr_m->evt_set_tid = lua_gettop(_curr_m->L);
        logu_("Registered for \"%s\" event\n", event_key);
    }
    else if (strcmp(event_key, "set_match_time")==0) {
        lua_pushvalue(L, -1);
        lua_xmove(L, _curr_m->L, 1);
        _curr_m->evt_set_match_time = lua_gettop(_curr_m->L);
        logu_("Registered for \"%s\" event\n", event_key);
    }
    else {
        logu_("WARN: trying to register for unknown event: \"%s\"\n",
            event_key);
    }
    lua_pop(L, 2);
    return 0;
}

static void push_context_table(lua_State *L)
{
    lua_newtable(L);

    char *sdir = (char*)Utf8::unicodeToUtf8(sider_dir);
    lua_pushstring(L, sdir);
    Utf8::free(sdir);
    lua_setfield(L, -2, "sider_dir"); 

    lua_pushcfunction(L, sider_context_register);
    lua_setfield(L, -2, "register");
}

static void push_env_table(lua_State *L, const wchar_t *script_name)
{
    char *sandbox[] = {
        "assert", "table", "pairs", "ipairs",
        "string", "math", "tonumber", "tostring",
        "unpack", "error", "_VERSION", "type",
    };

    lua_newtable(L);
    for (int i=0; i<sizeof(sandbox)/sizeof(char*); i++) {
        lua_pushstring(L, sandbox[i]);
        lua_getglobal(L, sandbox[i]);
        lua_settable(L, -3);
    }
    /* DISABLING FOR NOW, as this is a SECURITY issue
    // extra globals
    for (list<wstring>::iterator i = _config->_lua_extra_globals.begin();
            i != _config->_lua_extra_globals.end();
            i++) {
        char *name = (char*)Utf8::unicodeToUtf8(i->c_str());
        lua_pushstring(L, name);
        lua_getglobal(L, name);
        if (lua_isnil(L, -1)) {
            logu_("WARNING: Unknown Lua global: %s. Skipping it\n",
                name);
            lua_pop(L, 2);
        }
        else {
            lua_settable(L, -3);
        }
        Utf8::free(name);
    }
    */

    lua_pushstring(L, "log");
    lua_pushvalue(L, -2);  // upvalue for sider_log C-function
    lua_pushcclosure(L, sider_log, 1);
    lua_settable(L, -3);
    lua_pushstring(L, "_FILE");
    char *sname = (char*)Utf8::unicodeToUtf8(script_name);
    lua_pushstring(L, sname);
    Utf8::free(sname);
    lua_settable(L, -3);

    // set _G
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");

    // load some LuaJIT extenstions
    if (_config->_luajit_extensions_enabled) {
        char *ext[] = { "ffi", "bit" };
        for (int i=0; i<sizeof(ext)/sizeof(char*); i++) {
            lua_getglobal(L, "require");
            lua_pushstring(L, ext[i]);
            if (lua_pcall(L, 1, 1, 0) != 0) {
                const char *err = luaL_checkstring(L, -1);
                logu_("Problem loading LuaJIT module (%s): %s\n. "
                      "Skipping it.\n", ext[i], err);
                lua_pop(L, 1);
                continue;
            }
            else {
                lua_setfield(L, -2, ext[i]);
            }
        }
    }
}

bool _install_func(IMAGE_SECTION_HEADER *h);

DWORD install_func(LPVOID thread_param) {
    log_(L"DLL attaching to (%s).\n", module_filename);
    log_(L"Mapped into PES.\n");
    logu_("UTF-8 check: ленинградское время ноль часов ноль минут.\n");

    _is_game = true;

    InitializeCriticalSection(&_cs);

    log_(L"debug = %d\n", _config->_debug);
    log_(L"livecpk.enabled = %d\n", _config->_livecpk_enabled);
    log_(L"lookup-cache.enabled = %d\n", _config->_lookup_cache_enabled);
    log_(L"lua.enabled = %d\n", _config->_lua_enabled);
    log_(L"luajit.ext.enabled = %d\n", _config->_luajit_extensions_enabled);

    /* DISABLING FOR NOW, as this is a SECURITY issue
    for (list<wstring>::iterator it = _config->_lua_extra_globals.begin();
            it != _config->_lua_extra_globals.end();
            it++) {
        log_(L"Using lua extra global: %s\n", it->c_str());
    }
    */

    for (list<wstring>::iterator it = _config->_cpk_roots.begin();
            it != _config->_cpk_roots.end();
            it++) {
        log_(L"Using cpk.root: %s\n", it->c_str());
    }

    if (_config->_code_sections.size() == 0) {
        log_(L"No code sections specified in config: nothing to do then.");
        return 0;
    }


    if (_config->_lua_enabled) {
        // load and initialize lua modules
        L = luaL_newstate();
        luaL_openlibs(L);

        // prepare context table
        push_context_table(L);

        // load registered modules
        for (list<wstring>::iterator it = _config->_module_names.begin();
                it != _config->_module_names.end();
                it++) {
            // Use Win32 API to read the script into a buffer:
            // we do not want any nasty surprises with filename encodings
            wstring script_file(sider_dir);
            script_file += L"modules\\";
            script_file += it->c_str();

            log_(L"Loading module: %s ...\n", it->c_str());

            DWORD size = 0;
            HANDLE handle;
            handle = CreateFileW(
                script_file.c_str(),   // file to open
                GENERIC_READ,          // open for reading
                FILE_SHARE_READ,       // share for reading
                NULL,                  // default security
                OPEN_EXISTING,         // existing file only
                FILE_ATTRIBUTE_NORMAL, // normal file
                NULL);                 // no attr. template

            if (handle == INVALID_HANDLE_VALUE)
            {
                log_(L"PROBLEM: Unable to open file: %s\n", 
                    script_file.c_str());
                continue;
            }
                
            size = GetFileSize(handle, NULL);
            BYTE *buf = new BYTE[size+1];
            memset(buf, 0, size+1);
            DWORD bytesRead = 0;
            if (!ReadFile(handle, buf, size, &bytesRead, NULL)) {
                log_(L"PROBLEM: ReadFile error for lua module: %s\n", 
                    it->c_str());
                CloseHandle(handle);
                continue;
            }
            CloseHandle(handle);
            // script is now in memory

            char *mfilename = (char*)Utf8::unicodeToUtf8(it->c_str());
            string mfile(mfilename);
            Utf8::free(mfilename);
            int r = luaL_loadbuffer(L, (const char*)buf, size, mfile.c_str());
            delete buf;
            if (r != 0) {
                const char *err = lua_tostring(L, -1);
                logu_("Lua module loading problem: %s. "
                      "Skipping it\n", err);
                lua_pop(L, 1);
                continue;
            }

            // set environment
            push_env_table(L, it->c_str());
            lua_setfenv(L, -2);

            // run the module
            if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                logu_("Lua module initializing problem: %s. "
                      "Skipping it\n", err);
                lua_pop(L, 1);
                continue;
            }

            // check that module chunk is correctly constructed:
            // it must return a table 
            if (!lua_istable(L, -1)) {
                logu_("PROBLEM: Lua module (%s) must return a table. "
                      "Skipping it\n", mfile.c_str());
                lua_pop(L, 1);
                continue;
            }

            // now we have module table on the stack 
            // run its "init" method, with a context object
            lua_getfield(L, -1, "init");
            if (!lua_isfunction(L, -1)) {
                logu_("PROBLEM: Lua module (%s) does not "
                      "have \"init\" function. Skipping it.\n", 
                      mfile.c_str());
                lua_pop(L, 1);
                continue;
            }

            module_t *m = new module_t();
            memset(m, 0, sizeof(module_t));
            m->cache = new lookup_cache_t();
            m->L = luaL_newstate();
            _curr_m = m;

            lua_pushvalue(L, 1); // ctx
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                logu_("PROBLEM: Lua module (%s) \"init\" function "
                      "returned an error: %s\n", mfile.c_str(), err);
                logu_("Module (%s) is NOT activated\n", mfile.c_str());
                lua_pop(L, 1);
                // pop the module table too, since we are not using it
                lua_pop(L, 1);
            }
            else {
                logu_("OK: Lua module initialized: %s\n", mfile.c_str());
                logu_("gettop: %d\n", lua_gettop(L));

                // add to list of loaded modules
                _modules.push_back(m);
            }
        }
    }

    list<wstring>::iterator it = _config->_code_sections.begin();
    for (; it != _config->_code_sections.end(); it++) {
        char *section_name = (char*)Utf8::unicodeToUtf8(it->c_str());
        IMAGE_SECTION_HEADER *h = GetSectionHeader(section_name);
        Utf8::free(section_name);

        if (!h) {
            log_(L"Unable to find code section: %s. Skipping\n", it->c_str());
            continue;
        }
        if (h->Misc.VirtualSize < 0x1000000) {
            log_(L"Section too small: %s (%08x). Skipping\n", it->c_str(), h->Misc.VirtualSize);
            continue;
        }

        log_(L"Examining code section: %s\n", it->c_str());
        if (_install_func(h)) {
            break;
        }
    }
    return 0;
}

bool _install_func(IMAGE_SECTION_HEADER *h) {
    BYTE* base = (BYTE*)GetModuleHandle(NULL);
    base += h->VirtualAddress;
    log_(L"Searching code section at: %08x\n", base);
    bool result(false);

    if (_config->_black_bars_off) {
        BYTE *p = find_code_frag(base, h->Misc.VirtualSize,
            bb_pattern, sizeof(bb_pattern)-1);
        if (!p) {
            log_(L"Unable to patch: (black bars) code pattern not matched\n");
        }
        else {
            DWORD oldProtection;
            DWORD newProtection = PAGE_EXECUTE_READWRITE;

            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
            p = p + bb_offs;

            if (VirtualProtect(p, 8, newProtection, &oldProtection)) {
                memcpy(p, "\x90\x90", 2);
                VirtualProtect(p, 8, oldProtection, &newProtection);
                log_(L"Turning black bars off\n");
            }
            else {
                log_(L"PROBLEM with Virtual Protect.\n");
            }
        }
    }

    // trophy check
    {
        BYTE *p = find_code_frag(base, h->Misc.VirtualSize,
            trophy_pattern, sizeof(trophy_pattern)-1);
        if (!p) {
            log_(L"Unable to patch: (trophy check) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
            p = p + trophy_offs;

            log_(L"Enabling trophy map\n");
            hook_call_point((DWORD)p, trophy_map_cp, 6, 1);
        }
    }

    // team ids
    {
        BYTE *p;
        /*
        p = find_code_frag(base, h->Misc.VirtualSize,
            team_ids_pattern1, sizeof(team_ids_pattern1)-1);
        if (!p) {
            log_(L"Unable to patch: (team ids 1) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
            p = p + team_ids_off1;

            _team_ids_read_org = get_target_addr((DWORD)p);
            hook_call_point((DWORD)p, team_ids_read_cp, 6, 0);
        }
        */

        p = find_code_frag(base, h->Misc.VirtualSize,
            team_ids_pattern2, sizeof(team_ids_pattern2)-1);
        if (!p) {
            log_(L"Unable to patch: (team ids 2) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
            p = p + team_ids_off2;

            _team_info_write_org = get_target_addr((DWORD)p);
            hook_call_point((DWORD)p, team_info_write_cp, 6, 0);
        }
    }

    // num minutes
    {
        BYTE *p = find_code_frag(base, h->Misc.VirtualSize,
            minutes_pattern, sizeof(minutes_pattern)-1);
        if (!p) {
            log_(L"Unable to patch: (minutes set) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
            p = p + minutes_off;

            log_(L"Enabling set-num-minutes event\n");
            hook_call_point((DWORD)p, minutes_set_cp, 6, 1);
        }
    }

    // set default exhib settings
    {
        BYTE *p = find_code_frag(base, h->Misc.VirtualSize,
            settings_pattern, sizeof(settings_pattern)-1);
        if (!p) {
            log_(L"Unable to patch: (set-defaults) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
            p = p + settings_off;

            log_(L"Enabling set-defaults event\n");
            hook_call_point((DWORD)p, set_defaults_cp, 6, 1);
        }
    }

    // write tournament id
    {
        BYTE *p = find_code_frag(base, h->Misc.VirtualSize,
            write_tid_pattern, sizeof(write_tid_pattern)-1);
        if (!p) {
            log_(L"Unable to patch: (write-tid) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
            p = p + write_tid_off;

            log_(L"Enabling write-tid event\n");
            hook_call_point((DWORD)p, write_tournament_id_cp, 6, 1);
        }
    }

    // write exhibition id
    {
        BYTE *p = find_code_frag(base, h->Misc.VirtualSize,
            write_exhib_id_pattern, sizeof(write_exhib_id_pattern)-1);
        if (!p) {
            log_(L"Unable to patch: (write-exhib-id) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);
            p = p + write_exhib_id_off;

            log_(L"Enabling write-exhib-id event\n");
            hook_call_point((DWORD)p, write_exhib_id_cp, 6, 2);
        }
    }

    // fill in _tid* locations
    {
        BYTE *p = find_code_frag(base, h->Misc.VirtualSize,
            tid_func_pattern, sizeof(tid_func_pattern)-1);
        if (!p) {
            log_(L"Unable to match: (tid-func) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (p-base), p);

            // #1
            _tid_target1 = get_target_addr((DWORD)(p + tid_func_off1));
            _tid_target2 = (DWORD)(p + tid_func_off2);
            DWORD loc = get_target_addr(_tid_target2);
            _tid_addr1 = *(DWORD*)(loc + 1);

            log_(L"_tid_addr1: %p\n", _tid_addr1);
            log_(L"_tid_target1: %p\n", _tid_target1);
            log_(L"_tid_target2: %p\n", _tid_target2);
        }
    }

    if (_config->_livecpk_enabled) {
        BYTE *frag[5];
        frag[0] = lcpk_pattern_get_file_info;
        frag[1] = lcpk_pattern_at_read_file;
        frag[2] = lcpk_pattern_lookup_file;
        frag[3] = lcpk_pattern_before_read;
        frag[4] = lcpk_pattern_at_set_file_pointer;
        size_t frag_len[5];
        frag_len[0] = sizeof(lcpk_pattern_get_file_info)-1;
        frag_len[1] = sizeof(lcpk_pattern_at_read_file)-1;
        frag_len[2] = sizeof(lcpk_pattern_lookup_file)-1;
        frag_len[3] = sizeof(lcpk_pattern_before_read)-1;
        frag_len[4] = sizeof(lcpk_pattern_at_set_file_pointer)-1;
        int offs[5];
        offs[0] = 0;
        offs[1] = lcpk_offs_at_read_file;
        offs[2] = lcpk_offs_lookup_file;
        offs[3] = lcpk_offs_before_read;
        offs[4] = lcpk_offs_at_set_file_pointer;
        DWORD *addrs[5];
        addrs[0] = &_config->_hp_get_file_info;
        addrs[1] = &_config->_hp_at_read_file;
        addrs[2] = &_config->_hp_lookup_file;
        addrs[3] = &_config->_hp_before_read;
        addrs[4] = &_config->_hp_at_set_file_pointer;

        bool all_found(true);
        for (int j=0; j<5; j++) {
            BYTE *p = find_code_frag(base, h->Misc.VirtualSize, 
                frag[j], frag_len[j]);
            if (!p) {
                all_found = false;
                continue;
            }
            *(addrs[j]) = (DWORD)p + offs[j];
        }

        if (all_found) {
            hook_call_point(_config->_hp_get_file_info,
                lcpk_get_file_info_cp, 6, 3);

            hook_call_point(_config->_hp_at_read_file,
                lcpk_at_read_file, 0, 1);

            hook_call_point(_config->_hp_at_set_file_pointer,
                lcpk_at_set_file_pointer, 0, 1);

            _lookup_file_org = get_target_addr(_config->_hp_lookup_file);
            hook_call_point(_config->_hp_lookup_file,
                lcpk_lookup_file_cp, 6, 0);

            _before_read_org = get_target_addr(_config->_hp_before_read);
            hook_call_point(_config->_hp_before_read,
                lcpk_before_read_cp, 6, 0);

            result = true;
        }
        else {
            // report matching issues
            for (int j=0; j<3; j++) {
                DWORD addr = *(addrs[j]);
                if (!addr) {
                    log_(L"Unable to patch: "
                         L"lcpk(%d) code pattern not found\n", j); 
                }
            }
        }
    }

    DWORD oldProtection;
    DWORD newProtection = PAGE_EXECUTE_READWRITE;
    BYTE *c;

    if (_config->_free_select_sides) {
        place = find_code(base, h->Misc.VirtualSize);
        if (!place) {
            log_(L"Unable to patch: (free sides) code pattern not matched\n"); 
        }
        else {
            c = place-5;
            log_(L"Code pattern found at offset: %08x (%08x)\n", (c-base), c);  

            if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                memcpy(org_code, c, 5);
                memcpy(c, "\x66\xb8\x06\x00\x90", 5);
                VirtualProtect(c, 8, oldProtection, &newProtection);
                log_(L"Free select sides: enabled.\n");
                patched = true;
            }
            else {
                log_(L"PROBLEM with Virtual Protect.\n");
            }
        }
    }

    if (place && _config->_free_first_player) {
        c = find_free_first(place, h->Misc.VirtualSize);
        if (!c) {
            log_(L"Unable to patch: (free first player) code pattern not matched\n");
        }
        else {
            log_(L"Code pattern found at offset: %08x (%08x)\n", (c-base), c);  

            newProtection = PAGE_EXECUTE_READWRITE;
            if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                memcpy(org_code2, c, 3);
                memcpy(c, "\xb0\x00\x90", 3);
                VirtualProtect(c, 8, oldProtection, &newProtection);
                log_(L"Free first player: enabled.\n");
                patched2 = true;
            }
            else {
                log_(L"PROBLEM with Virtual Protect.\n");
            }
        }
    }

    if (_config->_cut_scenes) {
        place2 = find_cut_scenes(base, h->Misc.VirtualSize);
        if (!place2) {
            log_(L"Unable to patch: (cut-scenes) code pattern not matched\n"); 
        }
        else {
            c = place2;
            log_(L"Code pattern found at offset: %08x\n", (c-base));  

            newProtection = PAGE_EXECUTE_READWRITE;
            if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                memcpy(org_cut_scenes, c, 6);
                memcpy(c, "\x90\x90\x90\x90\x90\x90", 6);
                VirtualProtect(c, 8, oldProtection, &newProtection);
                log_(L"Cut scenes: enabled.\n");
                patched3 = true;
            }
            else {
                log_(L"PROBLEM with Virtual Protect.\n");
            }
        }
    }

    if (_config->_camera_sliders_max) {
        BYTE *frag[3];
        frag[0] = cam_sliders_code_pat1;
        frag[1] = cam_sliders_code_pat2;
        frag[2] = cam_sliders_code_pat3;
        size_t frag_len[3];
        frag_len[0] = sizeof(cam_sliders_code_pat1)-1;
        frag_len[1] = sizeof(cam_sliders_code_pat2)-1;
        frag_len[2] = sizeof(cam_sliders_code_pat3)-1;
        BYTE offs[3];
        offs[0] = cam_sliders_code_off1;
        offs[1] = cam_sliders_code_off2;
        offs[2] = cam_sliders_code_off3;

        for (int j=0; j<3; j++) {
            cam_places[j] = NULL;
            place = find_code_frag(base, h->Misc.VirtualSize, 
                frag[j], frag_len[j]);
            if (!place) {
                log_(L"Unable to patch: cam(%d) code pattern not matched\n", j); 
                continue;
            }
            c = place + offs[j];
            log_(L"Code pattern found at offset: %08x ( %p )\n", (place-base), place);  

            if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                c[0] = (BYTE)_config->_camera_sliders_max;
                VirtualProtect(c, 8, oldProtection, &newProtection);
                log_(L"Camera slider patched (%d) at offset %08x ( %p )\n", j, c-base, c);
                cam_places[j] = c;
                result = true;
            }
            else {
                log_(L"PROBLEM with Virtual Protect.\n");
            }
        }
    }

    if (_config->_camera_dynamic_wide_angle_enabled) {
        BYTE *frag[3];
        frag[0] = cam_dynamic_wide_pat1;
        frag[1] = cam_dynamic_wide_pat1;
        frag[2] = cam_dynamic_wide_pat3;
        size_t frag_len[3];
        frag_len[0] = sizeof(cam_dynamic_wide_pat1)-1;
        frag_len[1] = sizeof(cam_dynamic_wide_pat1)-1;
        frag_len[2] = sizeof(cam_dynamic_wide_pat3)-1;
        BYTE offs[3];
        offs[0] = cam_dynamic_wide_off1;
        offs[1] = cam_dynamic_wide_off2;
        offs[2] = cam_dynamic_wide_off3;
        BYTE *patch_code[3];
        patch_code[0] = cam_dynamic_wide_patch1;
        patch_code[1] = cam_dynamic_wide_patch2;
        patch_code[2] = cam_dynamic_wide_patch3;
        size_t patch_len[3];
        patch_len[0] = sizeof(cam_dynamic_wide_patch1)-1;
        patch_len[1] = sizeof(cam_dynamic_wide_patch2)-1;
        patch_len[2] = sizeof(cam_dynamic_wide_patch3)-1;
        BYTE *org_code[3];
        org_code[0] = cam_dynamic_wide_org1;
        org_code[1] = cam_dynamic_wide_org2;
        org_code[2] = cam_dynamic_wide_org3;

        for (int j=2; j>=0; j--) {
            cam_dynamic_wide_places[j] = NULL;
            place = find_code_frag(base, h->Misc.VirtualSize, 
                frag[j], frag_len[j]);
            if (!place) {
                log_(L"Unable to patch: dynamic_wide(%d) code pattern not matched\n", j); 
                continue;
            }
            c = place + offs[j];
            log_(L"Code pattern found at offset: %08x ( %p )\n", (place-base), place);  

            if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                memcpy(org_code[j], c, patch_len[j]);
                memcpy(c, patch_code[j], patch_len[j]);
                VirtualProtect(c, 8, oldProtection, &newProtection);
                log_(L"Dynamic Wide camera patched (%d) at offset %08x ( %p )\n", j, c-base, c);
                cam_dynamic_wide_places[j] = c;
                result = true;
            }
            else {
                log_(L"PROBLEM with Virtual Protect.\n");
            }
        }
    }

    return result || patched || patched2 || patched3;
}

wstring* _have_live_file(char *file_name)
{
    wchar_t unicode_filename[512];
    memset(unicode_filename, 0, sizeof(unicode_filename));
    Utf8::fUtf8ToUnicode(unicode_filename, file_name);

    wchar_t fn[512];
    for (list<wstring>::iterator it = _config->_cpk_roots.begin();
            it != _config->_cpk_roots.end();
            it++) {
        memset(fn, 0, sizeof(fn));
        wcscpy(fn, it->c_str());
        wchar_t *p = (unicode_filename[0] == L'\\') ? unicode_filename + 1 : unicode_filename;
        wcscat(fn, p);

        DWORD size = 0;
        HANDLE handle;
        handle = CreateFileW(fn,           // file to open
                           GENERIC_READ,          // open for reading
                           FILE_SHARE_READ,       // share for reading
                           NULL,                  // default security
                           OPEN_EXISTING,         // existing file only
                           FILE_ATTRIBUTE_NORMAL,  // normal file
                           NULL);                 // no attr. template

        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
            return new wstring(fn);
        }
    }

    return NULL;
}

wstring* have_live_file(char *file_name)
{
    if (!_config->_lookup_cache_enabled) {
        // no cache
        return _have_live_file(file_name);
    }
    unordered_map<string,wstring*>::iterator it;
    it = _lookup_cache.find(string(file_name));
    if (it != _lookup_cache.end()) {
        return it->second;
    }
    else {
        //wchar_t s[128];
        //memset(s, 0, sizeof(s));
        //Utf8::fUtf8ToUnicode(s, file_name);
        //log_(L"_lookup_cache MISS for (%s)\n", s);

        wstring* res = _have_live_file(file_name);
        _lookup_cache.insert(pair<string,wstring*>(string(file_name),res));
        return res;
    }
}

bool file_exists(wstring *fullpath)
{
    HANDLE handle = CreateFileW(
        fullpath->c_str(),     // file to open
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                 // no attr. template

    if (handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle);
        return true;
    }
    return false;
}

void module_set_home(module_t *m, DWORD team_id)
{
    if (m->evt_set_home_team != 0) {
        EnterCriticalSection(&_cs);
        lua_pushvalue(m->L, m->evt_set_home_team);
        lua_xmove(m->L, L, 1);
        // push params
        lua_pushvalue(L, 1); // ctx
        lua_pushinteger(L, team_id);
        if (lua_pcall(L, 2, 0, 0) != LUA_OK) {
            const char *err = luaL_checkstring(L, -1);
            logu_("[%d] lua ERROR: %s\n", GetCurrentThreadId(), err);
            lua_pop(L, 1);
        }
        LeaveCriticalSection(&_cs);
    }
}

void module_set_away(module_t *m, DWORD team_id)
{
    if (m->evt_set_away_team != 0) {
        EnterCriticalSection(&_cs);
        lua_pushvalue(m->L, m->evt_set_away_team);
        lua_xmove(m->L, L, 1);
        // push params
        lua_pushvalue(L, 1); // ctx
        lua_pushinteger(L, team_id);
        if (lua_pcall(L, 2, 0, 0) != LUA_OK) {
            const char *err = luaL_checkstring(L, -1);
            logu_("[%d] lua ERROR: %s\n", GetCurrentThreadId(), err);
            lua_pop(L, 1);
        }
        LeaveCriticalSection(&_cs);
    }
}

void module_set_tid(module_t *m, int tid)
{
    if (m->evt_set_tid != 0) {
        EnterCriticalSection(&_cs);
        lua_pushvalue(m->L, m->evt_set_tid);
        lua_xmove(m->L, L, 1);
        // push params
        lua_pushvalue(L, 1); // ctx
        lua_pushinteger(L, tid);
        if (lua_pcall(L, 2, 0, 0) != LUA_OK) {
            const char *err = luaL_checkstring(L, -1);
            logu_("[%d] lua ERROR: %s\n", GetCurrentThreadId(), err);
            lua_pop(L, 1);
        }
        LeaveCriticalSection(&_cs);
    }
}

bool module_set_match_time(module_t *m, DWORD *num_minutes)
{
    bool res(false);
    if (m->evt_set_match_time != 0) {
        EnterCriticalSection(&_cs);
        lua_pushvalue(m->L, m->evt_set_match_time);
        lua_xmove(m->L, L, 1);
        // push params
        lua_pushvalue(L, 1); // ctx
        lua_pushinteger(L, *num_minutes);
        if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
            const char *err = luaL_checkstring(L, -1);
            logu_("[%d] lua ERROR: %s\n", GetCurrentThreadId(), err);
        }
        else if (lua_isnumber(L, -1)) {
            int value = luaL_checkinteger(L, -1);
            *num_minutes = value;
            res = true;
        }
        lua_pop(L, 1);
        LeaveCriticalSection(&_cs);
    }
    return res;
}

bool module_rewrite(module_t *m, const char *file_name)
{
    bool res(false);
    EnterCriticalSection(&_cs);
    lua_pushvalue(m->L, m->evt_lcpk_rewrite);
    lua_xmove(m->L, L, 1);
    // push params
    lua_pushvalue(L, 1); // ctx
    lua_pushstring(L, file_name);
    if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
        const char *err = luaL_checkstring(L, -1);
        logu_("[%d] lua ERROR: %s\n", GetCurrentThreadId(), err);
    }
    else if (lua_isstring(L, -1)) {
        const char *s = luaL_checkstring(L, -1);
        strcpy((char*)file_name, s);
        res = true;
    }
    lua_pop(L, 1);
    LeaveCriticalSection(&_cs);
    return res;
}

void module_make_key(module_t *m, const char *file_name, char *key)
{
    if (m->evt_lcpk_make_key != 0) {
        EnterCriticalSection(&_cs);
        lua_pushvalue(m->L, m->evt_lcpk_make_key);
        lua_xmove(m->L, L, 1);
        // set default of empty key:
        // in case nil is returned, or an error occurs
        key[0] = '\0';
        // push params
        lua_pushvalue(L, 1); // ctx
        lua_pushstring(L, file_name);
        if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
            const char *err = luaL_checkstring(L, -1);
            logu_("[%d] lua ERROR: %s\n", GetCurrentThreadId(), err);
        }
        else if (lua_isstring(L, -1)) {
            const char *s = luaL_checkstring(L, -1);
            strcpy(key, s);
        }
        lua_pop(L, 1);
        LeaveCriticalSection(&_cs);
    }
    else {
        // assume filename is a key
        strcpy(key, file_name);
    }
}

wstring *module_get_filepath(module_t *m, const char *file_name, char *key)
{
    wstring *res = NULL;
    if (m->evt_lcpk_get_filepath != 0) {
        EnterCriticalSection(&_cs);
        lua_pushvalue(m->L, m->evt_lcpk_get_filepath);
        lua_xmove(m->L, L, 1);
        // push params
        lua_pushvalue(L, 1); // ctx
        lua_pushstring(L, file_name);
        lua_pushstring(L, (key[0]=='\0') ? NULL : key);
        if (lua_pcall(L, 3, 1, 0) != LUA_OK) {
            const char *err = luaL_checkstring(L, -1);
            logu_("[%d] lua ERROR: %s\n",
                GetCurrentThreadId(), err);
        }
        else if (lua_isstring(L, -1)) {
            const char *s = luaL_checkstring(L, -1);
            wchar_t *ws = Utf8::utf8ToUnicode((BYTE*)s);
            res = new wstring(ws);
            Utf8::free(ws);
        }
        lua_pop(L, 1);
        LeaveCriticalSection(&_cs);

        // verify that file exists
        if (res && !file_exists(res)) {
            delete res;
            res = NULL;
        }
    }
    return res;
}

void do_rewrite(char *file_name)
{
    list<module_t*>::iterator i;
    for (i = _modules.begin(); i != _modules.end(); i++) {
        module_t *m = *i;
        if (m->evt_lcpk_rewrite != 0) {
            if (module_rewrite(m, file_name)) {
                return;
            }
        }
    }
}

wstring* have_content(char *file_name)
{
    char key[512];
    list<module_t*>::iterator i;
    for (i = _modules.begin(); i != _modules.end(); i++) {
        module_t *m = *i;
        if (!m->evt_lcpk_make_key && !m->evt_lcpk_get_filepath) {
            // neither of callbacks is defined --> nothing to do
            continue;
        }

        module_make_key(m, file_name, key);
               
        if (_config->_lookup_cache_enabled) {
            unordered_map<string,wstring*>::iterator j;
            j = m->cache->find(key);
            if (j != m->cache->end()) {
                if (j->second != NULL) {
                    return j->second;
                }
                // this module does not have the file:
                // move on to next module
                continue;
            }
            else {
                wstring *res = module_get_filepath(m, file_name, key);

                // cache the lookup result
                m->cache->insert(pair<string,wstring*>(key, res));
                if (res) {
                    // we have a file: stop and return
                    return res;
                }
            }
        }
        else {
            // no cache: SLOW! ONLY use for troubleshooting
            wstring *res = module_get_filepath(m, file_name, key);
            if (res) {
                // we have a file: stop and return
                return res;
            }
        }
    }
    return NULL;
}

DWORD lcpk_get_file_info(struct FILE_INFO* file_info)
{
    char *filename = file_info->filename;
    size_t len = strlen(filename);
    char *replacement = filename + len + 1;
    filename = (replacement[0]!='\0') ? replacement : filename;

    wstring *fn;
    if (_config->_lua_enabled) do_rewrite(filename);
    fn = (_config->_lua_enabled) ? have_content(filename) : NULL;
    fn = (fn) ? fn : have_live_file(filename);

    if (fn != NULL) {
        DWORD size = 0;
        HANDLE handle;
        handle = CreateFileW(fn->c_str(),         // file to open
                           GENERIC_READ,          // open for reading
                           FILE_SHARE_READ,       // share for reading
                           NULL,                  // default security
                           OPEN_EXISTING,         // existing file only
                           FILE_ATTRIBUTE_NORMAL, // normal file
                           NULL);                 // no attr. template

        if (handle != INVALID_HANDLE_VALUE)
        {
            DBG log_(L"[%d] lcpk_get_file_info:: Found file:: %s\n",
                GetCurrentThreadId(), fn->c_str());

            size = GetFileSize(handle,NULL);

            DBG log_(L"[%d] lcpk_get_file_info:: Corrected size: %d --> %d (%08x)\n",
                GetCurrentThreadId(), file_info->size, size, size);

            file_info->offset = 0;
            file_info->size = size;
            file_info->size2 = size;

            CloseHandle(handle);
        }

        // clean-up wstring
        if (!_config->_lookup_cache_enabled) {
            delete fn;
        }
    }
    return 0;
}

void lcpk_get_file_info_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd 
        push ebp
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        mov eax,ebp
        sub eax,0x21c
        push eax  // addr of file_info struct on stack
        call lcpk_get_file_info
        add esp,0x04     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        and dword ptr ds:[edi+0x14],0  // execute replaced code
        and dword ptr ds:[edi+0x1c],0
        retn
    }
}

DWORD WINAPI lcpk_at_set_file_pointer(
    _In_        HANDLE hFile,
    _In_        LONG   lDistanceToMove,
    _Inout_opt_ PLONG  lpDistanceToMoveHigh,
    _In_        DWORD  dwMoveMethod)
{
    DWORD _ebp;
    READ_STRUCT *rs;

    __asm mov _ebp,ebp;
    rs = *(READ_STRUCT**)(_ebp + 0x7c);
    
    if (rs->dw4) {
        // switch file handle
        DBG log_(L"[%d] lcpk_at_set_file_pointer:: Switching handle: %08x --> %08x\n",
            GetCurrentThreadId(), hFile, rs->dw4);
        hFile = (HANDLE)rs->dw4;
    }

    DBG log_(L"[%d] lcpk_at_set_file_pointer:: (offset: %08x)\n",
        GetCurrentThreadId(), lDistanceToMove);
    return SetFilePointer(
        hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

BOOL WINAPI lcpk_at_read_file(
    _In_        HANDLE       hFile,
    _Out_       LPVOID       lpBuffer,
    _In_        DWORD        nNumberOfBytesToRead,
    _Out_opt_   LPDWORD      lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped) 
{
    DWORD _ebp;
    READ_STRUCT *rs;

    __asm mov _ebp,ebp;
    rs = *(READ_STRUCT**)(_ebp + 0x60);

    if (rs->dw4) {
        // switch file handle
        DBG log_(L"[%d] lcpk_at_read_file:: Switching handle: %08x --> %08x\n", 
            GetCurrentThreadId(), hFile, rs->dw4);
        hFile = (HANDLE)rs->dw4;
    }

    DWORD result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
        lpNumberOfBytesRead, lpOverlapped);

    DBG log_(L"[%d] lcpk_at_read_file:: Read into %p (num bytes: %08x)\n", 
        GetCurrentThreadId(),
        lpBuffer, *lpNumberOfBytesRead);

    if (rs->dw4) {
        CloseHandle((HANDLE)rs->dw4);
    }

    return result;
}

DWORD lcpk_before_read(struct READ_STRUCT* rs)
{
    if (rs && rs->filename) {
        DBG {
            logu_("[%d] lcpk_before_read:: Preparing read into buffer: %p from %s (%08x : %08x)\n",
                GetCurrentThreadId(),
                rs->buffer + rs->bufferOffset, rs->filename,
                rs->offset + rs->bufferOffset, rs->sizeRead);
        }

        wstring *fn = NULL;
        if (_config->_lua_enabled) do_rewrite(rs->filename);
        fn = (_config->_lua_enabled) ? have_content(rs->filename) : NULL;
        fn = (fn) ? fn : have_live_file(rs->filename);
        if (fn != NULL) {
            HANDLE handle;
            handle = CreateFileW(fn->c_str(),         // file to open
                               GENERIC_READ,          // open for reading
                               FILE_SHARE_READ,       // share for reading
                               NULL,                  // default security
                               OPEN_EXISTING,         // existing file only
                               FILE_ATTRIBUTE_NORMAL, // normal file
                               NULL);                 // no attr. template

            if (handle != INVALID_HANDLE_VALUE)
            {
                rs->dw4 = (DWORD)handle;
            }

            // clean-up wstring
            if (!_config->_lookup_cache_enabled) {
                delete fn;
            }
        }
    }
    return 0;
}

void lcpk_before_read_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push esi  // pointer to read_struct
        call lcpk_before_read
        add esp,0x04     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        jmp _before_read_org // jump to original target
    }
}

DWORD lcpk_lookup_file(char *filename, struct CPK_INFO* cpk_info)
{
    char tmp[256];
    if (cpk_info && cpk_info->cpk_filename) {
        wstring *fn;
        if (_config->_lua_enabled) do_rewrite(filename);
        fn = (_config->_lua_enabled) ? have_content(filename) : NULL;
        fn = (fn) ? fn : have_live_file(filename);
        if (fn != NULL) {
            if (memcmp(cpk_info->cpk_filename + 7, "dt36_win", 8)==0) {
                // replace with a known original filename
                strncpy(tmp, filename, sizeof(tmp));
                strcpy(filename, 
                    "\\common\\character0\\model\\character"
                    "\\appearance\\PlayerAppearance.bin");
                // keep the original name for later use
                strcpy(filename + strlen(filename) + 1, tmp);
            }
            else {
                // deliberately force load from dt36
                strcpy(filename, "\\not-a-file");
            }

            // clean-up wstring
            if (!_config->_lookup_cache_enabled) {
                delete fn;
            }
        }
    }
    return 0;
}

void lcpk_lookup_file_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push esi  // pointer cpk-info struct
        push edx  // pointer to filename on stack
        call lcpk_lookup_file
        add esp,0x08     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        jmp _lookup_file_org // jump to original target
    }
}

DWORD trophy_map(DWORD tournament_id)
{
    DWORD res = tournament_id;
    if (_config->_lua_enabled) {
        set_context_field_int("tournament_id", tournament_id);
        for (list<module_t*>::iterator it = _modules.begin();
                it != _modules.end();
                it++) {
            module_t *m = *it;
            if (m->evt_trophy_check != 0) {
                bool done(false);
                EnterCriticalSection(&_cs);
                lua_pushvalue(m->L, m->evt_trophy_check);
                lua_xmove(m->L, L, 1);
                // push params
                lua_pushvalue(L, 1); // ctx
                lua_pushinteger(L, tournament_id);
                if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
                    const char *err = luaL_checkstring(L, -1);
                    logu_("[%d] lua ERROR: %s\n",
                        GetCurrentThreadId(), err);
                }
                else if (lua_isnumber(L, -1)) {
                    res = (DWORD)luaL_checkint(L, -1);
                    done = true;
                }
                lua_pop(L, 1);
                LeaveCriticalSection(&_cs);
                if (done) {
                    break;
                }
            }
        }
    }

    return res;
}

void set_context_field_int(const char *name, int value)
{
    if (_config->_lua_enabled) {
        EnterCriticalSection(&_cs);
        lua_pushvalue(L, 1); // ctx
        lua_pushinteger(L, value);
        lua_setfield(L, -2, name);
        lua_pop(L, 1);
        LeaveCriticalSection(&_cs);
    }
}

void set_tid(int tid)
{
    _curr_tournament_id = tid;
    set_context_field_int("tournament_id", _curr_tournament_id);
    // lua callbacks
    if (_config->_lua_enabled) {
        list<module_t*>::iterator i;
        for (i = _modules.begin(); i != _modules.end(); i++) {
            module_t *m = *i;
            module_set_tid(m, _curr_tournament_id);
        }
    }
}

void trophy_map_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push eax  // tournament id
        call trophy_map
        add esp,0x04     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop ebp
        popfd
        mov dword ptr ds:[esi+0x2c08], eax
        mov dword ptr ss:[esp+4], eax
        retn
    }
}

DWORD team_ids_read(DWORD *home_team_id_encoded, DWORD *away_team_id_encoded)
{
    DWORD home=0, away=0;
    if (home_team_id_encoded) {
        home = ((*home_team_id_encoded) >> 0x0e) & 0xffff;
        set_context_field_int("home_team", home);
    }
    if (away_team_id_encoded) {
        away = ((*away_team_id_encoded) >> 0x0e) & 0xffff;
        set_context_field_int("away_team", away);
    }
    DBG log_(L"Match teams: HOME=%d, AWAY=%d\n", home, away);
    // lua callbacks
    if (_config->_lua_enabled) {
        list<module_t*>::iterator i;
        for (i = _modules.begin(); i != _modules.end(); i++) {
            module_t *m = *i;
            module_set_home(m, home);
            module_set_away(m, away);
        }
    }
    return 0;
}

void team_ids_read_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push eax  // away team-id-encoded
        push ecx  // home team-id-encoded
        call team_ids_read
        add esp,0x08     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        jmp _team_ids_read_org // jump to original target
    }
}

DWORD team_info_write(DWORD team_id_encoded, DWORD is_away)
{
    DWORD team_id = (team_id_encoded >> 0x0e) & 0xffff;
    if (is_away) {
        DBG log_(L"Exhibition AWAY team: %d\n", team_id);
        set_context_field_int("away_team", team_id);
    }
    else {
        DBG log_(L"Exhibition HOME team: %d\n", team_id);
        set_context_field_int("home_team", team_id);
    }
    // lua callbacks
    if (_config->_lua_enabled) {
        list<module_t*>::iterator i;
        for (i = _modules.begin(); i != _modules.end(); i++) {
            module_t *m = *i;
            if (is_away) {
                module_set_away(m, team_id);
            }
            else {
                module_set_home(m, team_id);
            }
        }
    }
    return 0;
}

void team_info_write_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push ecx  // home/away flag
        push edx  // team-id-encoded
        call team_info_write
        add esp,0x08     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        jmp _team_info_write_org // jump to original target
    }
}

DWORD minutes_set(DWORD settings_addr, DWORD num_minutes)
{
    WORD tid = *(WORD*)(settings_addr + 2);
    if (tid != 0xffff) {
        // non-exhibition: try to accelerate events
        // tournament id
        set_tid(convert_tournament_id(int(tid)));
        DBG log_(L"tournament id: %d\n", _curr_tournament_id);
        // team ids
        team_ids_read(
            (DWORD*)(settings_addr + 0xf4),   // home
            (DWORD*)(settings_addr + 0x614)); // away
    }
    DBG log_(L"match time: %d minutes\n", num_minutes);
    // lua callbacks
    if (_config->_lua_enabled) {
        list<module_t*>::iterator i;
        for (i = _modules.begin(); i != _modules.end(); i++) {
            module_t *m = *i;
            if (module_set_match_time(m, &num_minutes)) {
                break;
            }
        }
    }
    set_context_field_int("match_time", num_minutes);
    return num_minutes;
}

void minutes_set_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push ebx
        push ecx
        push edx
        push esi
        push edi
        mov al, byte ptr ss:[ebp+8]
        and eax,0xff
        push eax  // number of minutes
        push ecx  // settings addr
        call minutes_set
        add esp,0x08     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        mov byte ptr [ecx+0x14], al
        pop ebx
        pop ebp
        popfd
        retn
    }
}

int convert_tournament_id2()
{
    // [[26711b8]+0x34]+0x537b8 : for v1.04
    BYTE *p = *(BYTE**)_tid_addr1;
    if (p) {
        p = *(BYTE**)(p+0x34);
        if (p) {
            p = p + 0x537b8;
            DWORD res = -1;
            int target = _tid_target2;
            __asm {
                call target
                mov res,eax
            }
            return (int)res;
        }
    }
    return 0;
}

int convert_tournament_id(int id)
{
    // [[26711b8]+0x34]+0x537b8  : for v1.04
    BYTE *p = *(BYTE**)_tid_addr1;
    if (p) {
        p = *(BYTE**)(p+0x34);
        if (p) {
            p = p + 0x537b8;
            WORD tid = *(WORD*)(p+2);
            if (id == (int)tid) {
                // safe to call
                DWORD res = -1;
                int target = _tid_target1;
                int unc_tid = (int)tid;
                __asm {
                    mov eax,unc_tid
                    push eax
                    call target
                    mov res,eax
                    add esp,4
                }
                return (int)res;
            }
        }
    }
    return -1;
}

DWORD set_defaults(DWORD settings_addr)
{
    //BYTE *p = (BYTE*)settings_addr;
    //WORD id = *(WORD*)(p+2);
    //if (_curr_tournament_id != 0) {
    int new_tid = convert_tournament_id2();
    if (new_tid != _curr_tournament_id) {
        if ((new_tid == 0) || (_curr_tournament_id == 0 && new_tid != 6)) {
            set_tid(new_tid);
            DBG log_(L"set-defaults: tournament_id = %d\n",
                _curr_tournament_id);
        }
    }
    return 0;
}

void set_defaults_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push esi  // settings struct
        call set_defaults
        add esp,0x04     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        mov dword ptr ds:[esi],-1
        retn
    }
}

DWORD write_tournament_id(DWORD settings_addr)
{
    WORD tid = *(WORD*)(settings_addr + 2);
    set_tid(convert_tournament_id((int)tid));
    DBG log_(L"tournament_id = %d\n", _curr_tournament_id);
    return 0;
}

void write_tournament_id_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push esi  // settings struct
        call write_tournament_id
        add esp,0x04     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        mov edx, dword ptr ds:[edi+4]
        mov dword ptr ds:[esi+4], edx
        retn
    }
}

DWORD write_exhib_id(DWORD exhib_id)
{
    if (_curr_tournament_id == 0) {
        set_tid(convert_tournament_id2());
        DBG log_(L"exhib: tournament_id = %d\n", _curr_tournament_id);
    }
    return 0;
}

void write_exhib_id_cp()
{
    __asm {
        // IMPORTANT: when saving flags, use pusfd/popfd, because Windows
        // apparently checks for stack alignment and bad things happen, if it's not
        // DWORD-aligned. (For example, all file operations fail!)
        pushfd
        push ebp
        push eax
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push ecx  // exhibition id
        call write_exhib_id
        add esp,0x04     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        mov dword ptr ds:[esi+0x50], 3
        retn
    }
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) 
{
    wstring *match = NULL;
    INT result = FALSE;

    switch(Reason) {
        case DLL_PROCESS_ATTACH:
            myHDLL = hDLL;
            memset(module_filename, 0, sizeof(module_filename));
            if (GetModuleFileName(NULL, module_filename, MAX_PATH)==0) {
                return FALSE;
            }
            if (!init_paths()) {
                return FALSE;
            }
            //log_(L"DLL_PROCESS_ATTACH: %s\n", module_filename);
            if (skip_process(module_filename)) {
                return FALSE;
            }

            if (is_sider(module_filename)) {
                _is_sider = true;
                read_configuration(_config);
                if (!write_mapping_info(_config)) {
                    return FALSE;
                }
                return TRUE;
            }

            if (is_pes(module_filename, &match)) {
                read_configuration(_config);

                wstring version;
                get_module_version(hDLL, version);
                log_(L"===\n");
                log_(L"Sider DLL: version %s\n", version.c_str());
                log_(L"Filename match: %s\n", match->c_str());
                install_func(NULL);

                delete match;
                return TRUE;
            }

            return result;
            break;

        case DLL_PROCESS_DETACH:
            //log_(L"DLL_PROCESS_DETACH: %s\n", module_filename);

            if (_is_sider) {
                UnmapViewOfFile(_mh);
                CloseHandle(_mh);
            }

            if (_is_game) {
                log_(L"DLL detaching from (%s).\n", module_filename);
                log_(L"Unmapping from PES.\n");

                if (L) { lua_close(L); }
                DeleteCriticalSection(&_cs);

                DWORD oldProtection;
                DWORD newProtection = PAGE_EXECUTE_READWRITE;
                BYTE *c;

                if (patched && place) {
                    c = place-5;

                    if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                        memcpy(c, org_code, 5);
                        VirtualProtect(c, 8, oldProtection, &newProtection);
                        log_(L"Free select sides: restored original code\n");
                    }
                    else {
                        log_(L"PROBLEM with Virtual Protect.\n");
                    }
                }

                if (patched2 && place) {
                    c = place+12;

                    newProtection = PAGE_EXECUTE_READWRITE;
                    if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                        memcpy(c, org_code2, 3);
                        VirtualProtect(c, 8, oldProtection, &newProtection);
                        log_(L"Free first player: restored original code\n");
                    }
                    else {
                        log_(L"PROBLEM with Virtual Protect.\n");
                    }
                }

                if (patched3 && place2) {
                    c = place2;

                    newProtection = PAGE_EXECUTE_READWRITE;
                    if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                        memcpy(c, org_cut_scenes, 6);
                        VirtualProtect(c, 8, oldProtection, &newProtection);
                        log_(L"Cut scenes: restored original code\n");
                    }
                    else {
                        log_(L"PROBLEM with Virtual Protect.\n");
                    }
                }

                for (int j=0; j<3; j++) {
                    c = cam_places[j];
                    if (!c) {
                        continue;
                    }

                    newProtection = PAGE_EXECUTE_READWRITE;
                    if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                        c[0] = '\x0a';
                        VirtualProtect(c, 8, oldProtection, &newProtection);
                        log_(L"Cam sliders: restored original code (%d)\n", j);
                    }
                    else {
                        log_(L"PROBLEM with Virtual Protect.\n");
                    }
                }

                BYTE *org_code[3];
                org_code[0] = cam_dynamic_wide_org1;
                org_code[1] = cam_dynamic_wide_org2;
                org_code[2] = cam_dynamic_wide_org3;
                size_t org_len[3];
                org_len[0] = sizeof(cam_dynamic_wide_org1)-1;
                org_len[1] = sizeof(cam_dynamic_wide_org2)-1;
                org_len[2] = sizeof(cam_dynamic_wide_org3)-1;

                for (int j=2; j>=0; j--) {
                    c = cam_dynamic_wide_places[j];
                    if (!c) {
                        continue;
                    }

                    newProtection = PAGE_EXECUTE_READWRITE;
                    if (VirtualProtect(c, 8, newProtection, &oldProtection)) {
                        memcpy(c, org_code[j], org_len[j]);
                        VirtualProtect(c, 8, oldProtection, &newProtection);
                        log_(L"Dynamic Wide cam: restored original code (%d)\n", j);
                    }
                    else {
                        log_(L"PROBLEM with Virtual Protect.\n");
                    }
                }
            }
            break;

        case DLL_THREAD_ATTACH:
            //log_(L"DLL_THREAD_ATTACH: %s\n", module_filename);
            break;

        case DLL_THREAD_DETACH:
            //log_(L"DLL_THREAD_DETACH: %s\n", module_filename);
            break;

    }
 
    return TRUE;
}

//extern "C" __declspec(dllexport) int meconnect(
LRESULT CALLBACK meconnect(int code, WPARAM wParam, LPARAM lParam) 
{
    if (hookingThreadId == GetCurrentThreadId()) {
        log_(L"called in hooking thread!\n");
    }
    return CallNextHookEx(handle, code, wParam, lParam);
}

void setHook()
{
    handle = SetWindowsHookEx(WH_CBT, meconnect, myHDLL, 0);
    log_(L"--------------------\n");
    log_(L"handle = %p\n", handle);
}

void unsetHook()
{
    UnhookWindowsHookEx(handle);
}
