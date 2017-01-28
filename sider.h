#ifndef SIDER_H
#define SIDER_H

#include <string>

using namespace std;

#define SIDER_FM L"Local\\sider-3"

__declspec(dllexport) void setHook();
__declspec(dllexport) void unsetHook();
__declspec(dllexport) void log_(const wchar_t *format, ...);
__declspec(dllexport) void start_log_(const wchar_t *format, ...);
__declspec(dllexport) void get_module_version(HMODULE, wstring&);

#endif
