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

#define DBG if (_config->_debug)

using namespace std;

static DWORD get_target_addr(DWORD call_location);
static void hook_call_point(DWORD addr, void* func, int codeShift, int numNops, bool addRetn=false);

void lcpk_lookup_file_cp();
void lcpk_get_file_info_cp();
void lcpk_before_read_cp();

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

unordered_map<string,wstring*> _lookup_cache;

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

bool is_game(false);

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

struct mapping_t {
    size_t var_size;
    int mapping_option;
};

class config_t {
public:
    bool _debug;
    bool _livecpk_enabled;
    bool _lookup_cache_enabled;
    int _dll_mapping_option;
    wstring _section_name;
    list<wstring> _code_sections;
    list<wstring> _cpk_roots;
    list<wstring> _exe_names;
    bool _free_select_sides;
    bool _free_first_player;
    bool _cut_scenes;
    int _camera_sliders_max;
    bool _camera_dynamic_wide_angle_enabled;
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
                 _dll_mapping_option(0),
                 _free_select_sides(false),
                 _free_first_player(false),
                 _cut_scenes(false),
                 _camera_sliders_max(0),
                 _camera_dynamic_wide_angle_enabled(false),
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

        _dll_mapping_option = GetPrivateProfileInt(_section_name.c_str(),
            L"dll-mapping.option", _dll_mapping_option,
            config_ini);
        
        _free_select_sides = GetPrivateProfileInt(_section_name.c_str(),
            L"free.select.sides", _free_select_sides,
            config_ini);

        _free_first_player = GetPrivateProfileInt(_section_name.c_str(),
            L"free.first.player", _free_first_player,
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
    FILE *file = _wfopen(dll_log, L"a+");
    if (file) {
        va_list params;
        va_start(params, format);
        vfwprintf(file, format, params);
        va_end(params);
        fclose(file);
    }
}

__declspec(dllexport) void start_log_(const wchar_t *format, ...)
{
    FILE *file = _wfopen(dll_log, L"wt");
    if (file) {
        va_list params;
        va_start(params, format);
        vfwprintf(file, format, params);
        va_end(params);
        fclose(file);
    }
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

static void read_mapping_info(mapping_t *mt, BYTE **patterns)
{
    wstring fname(sider_dir);
    fname += L"sider-map.dat";
    FILE *f = _wfopen(fname.c_str(), L"rb");
    if (!f) {
        mt->var_size = 0;
        mt->mapping_option = 0;
        return;
    }

    fread(mt, sizeof(*mt), 1, f);
    *patterns = new BYTE[mt->var_size];
    fread(*patterns, mt->var_size, 1, f);
    fclose(f);
}

static bool write_mapping_info(config_t *config, mapping_t *mt)
{
    mt->var_size = 0;
    mt->mapping_option = config->_dll_mapping_option;

    // create mapping info
    wstring fname(sider_dir);
    fname += L"sider-map.dat";
    FILE *f = _wfopen(fname.c_str(), L"wb");
    if (!f) {
        log_(L"FATAL: Problem creating mapping info\n");
        return false;
    }
    fwrite(mt, sizeof(*mt), 1, f);

    for (list<wstring>::iterator it = config->_exe_names.begin();
            it != _config->_exe_names.end();
            it++) {
        size_t len = it->size();
        fwrite(it->c_str(), len*sizeof(wchar_t), 1, f);
        fwrite(L"\0", sizeof(wchar_t), 1, f);
        mt->var_size += (len + 1)*sizeof(wchar_t);
    }

    // write updated structure header
    fseek(f, 0, SEEK_SET);
    fwrite(mt, sizeof(*mt), 1, f);
    fclose(f);
    return true;
}

static bool is_pes(wchar_t* name, mapping_t *mt,
    BYTE *patterns, wstring** match)
{
    wchar_t *filename = wcsrchr(name, L'\\');
    if (filename) {
        wchar_t *s = (wchar_t*)patterns;
        wchar_t *end = (wchar_t*)(patterns + mt->var_size);
        while (s < end) {
            if (wcsicmp(filename, s) == 0) {
                *match = new wstring(s);
                return true;
            }
            s = s + wcslen(s) + 1;
        }
    }
    return false;
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

bool _install_func(IMAGE_SECTION_HEADER *h);

DWORD install_func(LPVOID thread_param) {
    log_(L"DLL attaching to (%s).\n", module_filename);
    log_(L"Mapped into PES.\n");

    is_game = true;

    log_(L"debug = %d\n", _config->_debug);
    log_(L"livecpk.enabled = %d\n", _config->_livecpk_enabled);
    log_(L"lookup-cache.enabled = %d\n", _config->_lookup_cache_enabled);
    log_(L"dll-mapping.option = %d\n", _config->_dll_mapping_option);

    for (list<wstring>::iterator it = _config->_cpk_roots.begin();
            it != _config->_cpk_roots.end();
            it++) {
        log_(L"Using cpk.root: %s\n", it->c_str());
    }

    if (_config->_code_sections.size() == 0) {
        log_(L"No code sections specified in config: nothing to do then.");
        return 0;
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

DWORD lcpk_get_file_info(struct FILE_INFO* file_info)
{
    char *filename = file_info->filename;
    size_t len = strlen(filename);
    char *replacement = filename + len + 1;
    filename = (replacement[0]!='\0') ? replacement : filename;

    wstring *fn = have_live_file(filename);
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
            DBG log_(L"Found file:: %s\n", fn->c_str());
            size = GetFileSize(handle,NULL);
            DBG log_(L"Corrected size: %d --> %d\n", file_info->size, size);

            file_info->offset = 0;
            file_info->size = size;
            file_info->size2 = size;

            CloseHandle(handle);
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
    //DBG log_(L"SetFilePointer: _ebp: %p\n", _ebp);
    rs = *(READ_STRUCT**)(_ebp + 0x7c);
    
    if (rs->dw4) {
        // switch file handle
        DBG log_(L"Switching handle: %08x --> %08x\n", hFile, rs->dw4);
        hFile = (HANDLE)rs->dw4;
    }

    DBG log_(L"SetFilePointer: (offset: %08x)\n", lDistanceToMove);
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
    //DBG log_(L"ReadFile: _ebp: %p\n", _ebp);
    rs = *(READ_STRUCT**)(_ebp + 0x60);

    if (rs->dw4) {
        // switch file handle
        DBG log_(L"Switching handle: %08x --> %08x\n", hFile, rs->dw4);
        hFile = (HANDLE)rs->dw4;
    }

    DBG log_(L"ReadFile: into %p (num bytes: %08x)\n", lpBuffer, nNumberOfBytesToRead);
    DWORD result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
        lpNumberOfBytesRead, lpOverlapped);

    if (rs->dw4) {
        CloseHandle((HANDLE)rs->dw4);
    }

    return result;
}

DWORD lcpk_before_read(struct READ_STRUCT* rs)
{
    if (rs && rs->filename) {
        DBG {
            wchar_t *s = Utf8::utf8ToUnicode((BYTE*)rs->filename);
            log_(L"Preparing read into buffer: %p from %s (%08x : %08x)\n",
                rs->buffer + rs->bufferOffset, s,
                rs->offset + rs->bufferOffset, rs->sizeRead);
            Utf8::free(s);
        }

        wstring *fn = have_live_file(rs->filename);
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
    char tmp[128];
    if (cpk_info && cpk_info->cpk_filename) {
        if (have_live_file(filename) != NULL) {
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

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) 
{
    wstring *match = NULL;
    INT result = FALSE;
    mapping_t mt;
    BYTE *patterns;

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

            read_mapping_info(&mt, &patterns);
            result = (mt.mapping_option == 1) ? TRUE : FALSE;

            if (is_pes(module_filename, &mt, patterns, &match)) {
                read_configuration(_config);

                wstring version;
                get_module_version(hDLL, version);
                log_(L"===\n");
                log_(L"Sider DLL: version %s\n", version.c_str());
                log_(L"Filename match: %s\n", match->c_str());
                install_func(NULL);

                delete match;
                delete patterns;
                return TRUE;
            }

            if (is_sider(module_filename)) {
                read_configuration(_config);
                if (!write_mapping_info(_config, &mt)) {
                    return FALSE;
                }
                return TRUE;
            }

            return result;
            break;

        case DLL_PROCESS_DETACH:
            //log_(L"DLL_PROCESS_DETACH: %s\n", module_filename);

            if (is_game) {
                log_(L"DLL detaching from (%s).\n", module_filename);
                log_(L"Unmapping from PES.\n");

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
