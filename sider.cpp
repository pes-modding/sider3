#define UNICODE

//#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <list>
#include <string>
#include <hash_map>
#include "imageutil.h"
#include "sider.h"
#include "utf8.h"

using namespace std;
using namespace stdext;

static DWORD get_target_addr(DWORD call_location);
static void hook_call_point(DWORD addr, void* func, int codeShift, int numNops, bool addRetn=false);

void lcpk_get_buffer_size_cp();
void lcpk_create_buffer_cp();
void lcpk_after_read_cp();
void lcpk_lookup_file_cp();

static DWORD dwThreadId;
static DWORD hookingThreadId = 0;
static HMODULE myHDLL;
static HHOOK handle;

hash_map<DWORD*,string> _assoc;

wchar_t module_filename[MAX_PATH];
wchar_t dll_log[MAX_PATH];
wchar_t dll_ini[MAX_PATH];

struct CPK_INFO {
    DWORD dw0[8];
    DWORD dw1;
    char *cpk_filename;
    DWORD dw2[6];
};

struct READ_STRUCT {
    DWORD dw0;
    DWORD cpkInfoTableAddr;
    DWORD dw1[22];
    DWORD size;
    BYTE *buffer;
    DWORD dw2[0xd0/4];
    char filename[0x80];
};

// original call destination of "lookup_file"
static DWORD _lookup_file_org = 0;

bool is_game(false);
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
    char *_code_section;
    wstring _section_name;
    wstring _cpk_root;
    list<wstring> _exe_names;
    bool _free_select_sides;
    bool _free_first_player;
    bool _cut_scenes;
    int _camera_sliders_max;
    bool _camera_dynamic_wide_angle_enabled;
    DWORD _hp_get_buffer_size;
    DWORD _hp_create_buffer;
    DWORD _hp_after_read;
    DWORD _hp_lookup_file;

    config_t(const wstring& section_name, const wchar_t* config_ini) : 
                 _section_name(section_name),
                 _debug(false),
                 _free_select_sides(false),
                 _free_first_player(false),
                 _cut_scenes(false),
                 _camera_sliders_max(0),
                 _camera_dynamic_wide_angle_enabled(false),
                 _hp_get_buffer_size(0),
                 _hp_create_buffer(0),
                 _hp_after_read(0),
                 _hp_lookup_file(0)
    {
        _code_section = strdup(".text");
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
                wstring root;
                _exe_names.push_back(value);
            }
            else if (wcscmp(L"code.section", key.c_str())==0) {
                if (_code_section) free(_code_section);
                _code_section = (char *)Utf8::unicodeToUtf8(value.c_str());
            }
            else if (wcscmp(L"cpk.root", key.c_str())==0) {
                _cpk_root = value;
            }
            else if (wcscmp(L"hook.get-buffer-size", key.c_str())==0) {
                swscanf(value.c_str(), L"0x%x", &_hp_get_buffer_size);
            }
            else if (wcscmp(L"hook.create-buffer", key.c_str())==0) {
                swscanf(value.c_str(), L"0x%x", &_hp_create_buffer);
            }
            else if (wcscmp(L"hook.after-read", key.c_str())==0) {
                swscanf(value.c_str(), L"0x%x", &_hp_after_read);
            }
            else if (wcscmp(L"hook.lookup-file", key.c_str())==0) {
                swscanf(value.c_str(), L"0x%x", &_hp_lookup_file);
            }

            p += wcslen(p) + 1;
        }

        _debug = GetPrivateProfileInt(_section_name.c_str(),
            L"debug", _debug,
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

    ~config_t() {
        if (_code_section) free(_code_section);
    }
};

config_t* _config;

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

static bool is_pes(wchar_t* name)
{
    if (_config) {
        list<wstring>::iterator it;
        for (it = _config->_exe_names.begin(); 
                it != _config->_exe_names.end();
                it++) {
            wchar_t *filename = wcsrchr(name, L'\\');
            if (filename) {
                if (wcsicmp(filename, it->c_str()) == 0) {
                    log_(L"===\n");
                    log_(L"Filename match: %s\n", it->c_str());
                    return true;
                }
            }
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

DWORD install_func(LPVOID thread_param) {
    log_(L"DLL attaching to (%s).\n", module_filename);
    log_(L"Mapped into PES.\n");

    is_game = true;

    BYTE* base = (BYTE*)GetModuleHandle(NULL);
    IMAGE_SECTION_HEADER* h;
    h = GetSectionHeader(_config->_code_section);
    if (!h) {
        log_(L"Unable to find code section. Stopping here\n");
        return -1;
    }

    hook_call_point(_config->_hp_get_buffer_size,
        lcpk_get_buffer_size_cp, 6, 1);
    //hook_call_point(_config->_hp_create_buffer,
    //    lcpk_create_buffer_cp, 6, 1);
    hook_call_point(_config->_hp_after_read,
        lcpk_after_read_cp, 6, 2);

    _lookup_file_org = get_target_addr(_config->_hp_lookup_file);
    hook_call_point(_config->_hp_lookup_file,
        lcpk_lookup_file_cp, 6, 0);

    base += h->VirtualAddress;

    log_(L"Starting code section: %08x\n", base);

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
            }
            else {
                log_(L"PROBLEM with Virtual Protect.\n");
            }
        }
    }

    return 0;
}

bool have_live_file(char *file_name)
{
    wchar_t unicode_filename[512];
    memset(unicode_filename, 0, sizeof(unicode_filename));
    Utf8::fUtf8ToUnicode(unicode_filename, file_name);

    wchar_t fn[512];
    memset(fn, 0, sizeof(fn));
    wcscpy(fn, _config->_cpk_root.c_str());
    wcscat(fn, unicode_filename);

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
        return true;
    }

    return false;
}

DWORD lcpk_get_buffer_size(char* file_name, DWORD* p_org_size)
{
    wchar_t unicode_filename[512];
    memset(unicode_filename, 0, sizeof(unicode_filename));
    Utf8::fUtf8ToUnicode(unicode_filename, file_name);

    // simple replacement
    wchar_t fn[512];
    memset(fn, 0, sizeof(fn));
    wcscpy(fn, _config->_cpk_root.c_str());
    wcscat(fn, unicode_filename);

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
        log_(L"Found file:: %s\n", fn);
        size = GetFileSize(handle,NULL);
        if (size > *p_org_size) {
            log_(L"Corrected size: %d --> %d\n", *p_org_size, size);
            *p_org_size = size;
        }
        else {
            log_(L"No need for size correction: %d (old) >= %d (new)\n",
                    *p_org_size, size);
        }
        CloseHandle(handle);
    }

    log_(L"File: %s, size: %d\n", unicode_filename, *p_org_size);
    return 0;
}

void lcpk_get_buffer_size_cp()
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
        lea eax,dword ptr ss:[esp+0x20+32]
        push eax // pointer to org-size
        mov eax,dword ptr ss:[esp+8+32+4]
        push eax // file name
        call lcpk_get_buffer_size
        add esp,0x08     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        //mov ecx,dword ptr ss:[ebp-0x40] // execute replaced code
        mov ecx,dword ptr ss:[esp+0x24] // execute replaced code
        retn
    }
}

DWORD lcpk_create_buffer(DWORD* file_name_addr, DWORD* buffer)
{
    if (file_name_addr) {
        char *file_name = NULL;
        DWORD name_buffer_size = *(DWORD*)((DWORD)file_name_addr + 0x10);
        log_(L"name_buffer_size: %d\n", name_buffer_size);
        if (name_buffer_size > 0 && name_buffer_size < 16) {
            file_name = (char*)file_name_addr; // on stack directly
        } else {
            file_name = *(char**)file_name_addr; // elsewhere
        }
            
        // associate buffer address with filename
        string name(file_name);
        
        wchar_t s[512];
        memset(s, 0, sizeof(s));
        Utf8::fUtf8ToUnicode(s, file_name);
        log_(L"Association: %p <-- %s\n", buffer, s); 

        pair<hash_map<DWORD*,string>::iterator,bool> ires =
            _assoc.insert(pair<DWORD*,string>(buffer,name));
        if (!ires.second)
        {
            log_(L"WARNING: updating existing entry (buffer: %p)\n", buffer);
        }
    }
 
    return (DWORD)buffer;
}

void lcpk_create_buffer_cp()
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
        push eax // buffer address
        lea ebx,dword ptr ss:[esp+0x28+32+8]
        push ebx // file name
        call lcpk_create_buffer
        add esp,0x08     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        mov dword ptr ds:[esi+0x38],eax // execute replaced code
        cmp dword ptr ds:[esi+0x38],ebx
        retn
    }
}

DWORD lcpk_after_read(struct READ_STRUCT* rs)
{
    if (rs) {
        if (rs->filename) {
            wchar_t s[512];
            memset(s, 0, sizeof(s));
            Utf8::fUtf8ToUnicode(s, rs->filename);

            log_(L"READ bytes into (%p) from: %s (0x%x)\n",
                    rs->buffer, s, rs->size);

            // simple replacement
            wchar_t fn[512];
            memset(fn, 0, sizeof(fn));
            wcscpy(fn, _config->_cpk_root.c_str());
            wcscat(fn, s);

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
                log_(L"Found file:: %s\n", fn);
                size = GetFileSize(handle,NULL);
                DWORD bytesRead = 0;
                ReadFile(handle, rs->buffer, size, &bytesRead, NULL); 
                if (bytesRead > 0) {
                    log_(L"Read replacement data (%d bytes). HOORAY!\n", bytesRead);
                }
                CloseHandle(handle);
            }
 
        }
        else {
            log_(L"rs (buffer: %p), but no filename\n", rs->buffer);
        }
    }
    return 0;
}

void lcpk_after_read_cp()
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
        push esi // struct address
        call lcpk_after_read
        add esp,0x04     // pop parameters
        pop edi
        pop esi
        pop edx
        pop ecx
        pop ebx
        pop eax
        pop ebp
        popfd
        mov dword ptr ds:[esi+0x10], 1  // execute replaced code
        retn
    }
}

DWORD lcpk_lookup_file(char *filename, struct CPK_INFO* cpk_info)
{
    if (cpk_info && cpk_info->cpk_filename) {
        if (memcmp(
            //cpk_info->cpk_filename, ".\\Data\\dt00_win.cpk")==0) {
            cpk_info->cpk_filename + 7, "dt00_win", 8)==0) {
            if (have_live_file(filename)) {
                // replace with a known original file
                strcpy(filename, "\\common\\etc\\TeamColor.bin");
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
    wchar_t *dot;

    switch(Reason) {
        case DLL_PROCESS_ATTACH:
            myHDLL = hDLL;
            memset(dll_log, 0, sizeof(dll_log));
            GetModuleFileName(hDLL, dll_log, MAX_PATH);
            dot = wcsrchr(dll_log, L'.');
            wcscpy(dot, L".log");

            memset(dll_ini, 0, sizeof(dll_ini));
            wcscpy(dll_ini, dll_log);
            dot = wcsrchr(dll_ini, L'.');
            wcscpy(dot, L".ini");

            memset(module_filename, 0, sizeof(module_filename));
            GetModuleFileName(NULL, module_filename, MAX_PATH);
            //log_(L"DLL_PROCESS_ATTACH: %s\n", module_filename);

            if (!_config) {
                read_configuration(_config);
            }

            if (is_pes(module_filename)) {
                if (CreateThread(NULL, //Choose default security
                        0, //Default stack size
                        (LPTHREAD_START_ROUTINE)&install_func,
                        //Routine to execute
                        NULL, //(LPVOID) &i, //Thread parameter
                        0, //Immediately run the thread
                        &dwThreadId) == NULL) {
                    log_(L"PROBLEM creating thread.\n");
                }
            }
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
    handle = SetWindowsHookEx(WH_KEYBOARD, meconnect, myHDLL, 0);
    log_(L"---\n");
    log_(L"handle = %p\n", handle);
}

void unsetHook()
{
    UnhookWindowsHookEx(handle);
}
