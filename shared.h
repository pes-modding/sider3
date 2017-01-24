#ifndef SIDER_SHARED_H
#define SIDER_SHARED_H

struct WSTR_INFO {
    size_t count;
    wchar_t *s[1];
};

#pragma data_seg(".sidrsh")
BYTE _shared_data[4096] = "\0\0\0\0\0\0\0\0";
#pragma data_seg()

#endif
