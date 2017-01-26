#ifndef SIDER_H
#define SIDER_H

#include <string>
#include "shared.h"

using namespace std;

__declspec(dllexport) void setHook();
__declspec(dllexport) void unsetHook();
__declspec(dllexport) void log_(const wchar_t *format, ...);
__declspec(dllexport) void start_log_(const wchar_t *format, ...);
__declspec(dllexport) void get_module_version(HMODULE, wstring&);
__declspec(dllexport) struct WSTR_INFO *get_wi();
__declspec(dllexport) int *get_dll_mapping_option();

#endif
