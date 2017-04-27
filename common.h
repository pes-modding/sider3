#ifndef SIDER_COMMON_H
#define SIDER_COMMON_H

#include "windows.h"

BYTE* find_code_frag(BYTE*, DWORD, BYTE*, size_t);
DWORD get_target_addr(DWORD call_location);
void hook_call_point(DWORD addr, void* func, int codeShift, int numNops, bool addRetn=false);

#endif
