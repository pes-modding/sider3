#define UNICODE

#include <stdio.h>
#include <string>

#include "common.h"

extern wchar_t dll_log[MAX_PATH];

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

DWORD get_target_addr(DWORD call_location)
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

void hook_call_point(
    DWORD addr, void* func, int codeShift, int numNops, bool addRetn)
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

