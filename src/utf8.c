#include <stdio.h>
#include <windows.h>
#include "utf8.h"

int utf8_encode(unsigned short c, unsigned char *out)
{
    if(c < 0x80) {
        *out = c & 0x7f;
        return 1;
    }
    else if(c < 0x800) {
        *out = 0xc0 + ((c >> 8) << 2) + (c >> 6);
        out[1] = 0x80 + (c & 0x3f);
        return 2;
    }
    else {
        *out = 0xe0 + (c >> 12);
        out[1] = 0x80 + (((c >> 8) & 0x1f) << 2) + ((c >> 6) & 0x3);
        out[2] = 0x80 + (c & 0x3f);
        return 3;
    }
}

int utf8_length(unsigned short x)
{
    unsigned char buf[3];
    return utf8_encode(x, buf);
}

int utf8_bytecnt_ascii(const char *s, int len)
{
    if(len < 0) len = strlen(s);

    int ret = 0;
    while (len-- != 0) {
        ret += utf8_length(*s++);
    }
    return ret;
}

int utf8_bytecnt_unicode(const wchar_t *s, int len)
{
    if(len < 0) len = lstrlenW(s);

    int ret = 0;
    while (len-- != 0) {
        ret += utf8_length(*s++);
    }
    return ret;
}

char *utf8_string(const char *s, int len)
{
    if(len < 0) len = strlen(s);

    int encoded_length = utf8_bytecnt_ascii(s, len);
    char *utf8string = (char *) malloc(encoded_length+4);
    *((int *) utf8string) = encoded_length;
    int pos = 4;

    while (len-- != 0) {
        pos += utf8_encode(*s++, (unsigned char *) &utf8string[pos]);
    }
    return utf8string;
}

char *utf8_wstring(const wchar_t *s, int len)
{
    if(len < 0) len = lstrlenW(s);

    int encoded_length = utf8_bytecnt_unicode(s, len);
    char *utf8string = (char *) malloc(encoded_length+4);
    *((int *) utf8string) = encoded_length;
    int pos = 4;

    while (len-- != 0) {
        pos += utf8_encode(*s++, (unsigned char *) &utf8string[pos]);
    }
    return utf8string;
}
