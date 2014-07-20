#ifndef MONITOR_UTF8_H
#define MONITOR_UTF8_H

#include <windows.h>

int utf8_encode(unsigned short x, unsigned char *out);
int utf8_length(unsigned short x);

int utf8_bytecnt_ascii(const char *s, int len);
int utf8_bytecnt_unicode(const wchar_t *s, int len);

char *utf8_string(const char *s, int len);
char *utf8_wstring(const wchar_t *s, int len);

#endif
