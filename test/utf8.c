/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2015-2017 Cuckoo Foundation.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/// FINISH= yes
/// FREE= yes
/// PIPE= yes

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "hooking.h"
#include "memory.h"
#include "native.h"
#include "pipe.h"
#include "utf8.h"

#define assert(expr) \
    if((expr) == 0) { \
        pipe("CRITICAL:Test didn't pass: %z", #expr); \
    } \
    else { \
        pipe("INFO:Test passed: %z", #expr); \
    }

int main()
{
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);

    hook_init(GetModuleHandle(NULL));
    mem_init();
    assert(native_init() == 0);

    uint8_t buf[16]; uint16_t val[2];

    assert(utf8_encode(0x00000001, buf) == 1 && memcmp(buf, "\x01", 1) == 0);
    assert(utf8_encode(0x0000007f, buf) == 1 && memcmp(buf, "\x7f", 1) == 0);
    assert(utf8_encode(0x00000080, buf) == 2 && memcmp(buf, "\xc2\x80", 2) == 0);
    assert(utf8_encode(0x000007ff, buf) == 2 && memcmp(buf, "\xdf\xbf", 2) == 0);
    assert(utf8_encode(0x00000800, buf) == 3 && memcmp(buf, "\xe0\xa0\x80", 3) == 0);
    assert(utf8_encode(0x0000ffff, buf) == 3 && memcmp(buf, "\xef\xbf\xbf", 3) == 0);
    assert(utf8_encode(0x00010000, buf) == 4 && memcmp(buf, "\xf0\x90\x80\x80", 4) == 0);
    assert(utf8_encode(0x001fffff, buf) == 4 && memcmp(buf, "\xf7\xbf\xbf\xbf", 4) == 0);
    assert(utf8_encode(0x00200000, buf) == 5 && memcmp(buf, "\xf8\x88\x80\x80\x80", 5) == 0);
    assert(utf8_encode(0x03ffffff, buf) == 5 && memcmp(buf, "\xfb\xbf\xbf\xbf\xbf", 5) == 0);
    assert(utf8_encode(0x04000000, buf) == 6 && memcmp(buf, "\xfc\x84\x80\x80\x80\x80", 6) == 0);
    assert(utf8_encode(0x7fffffff, buf) == 6 && memcmp(buf, "\xfd\xbf\xbf\xbf\xbf\xbf", 6) == 0);

    // It's kind of a hassle to get utf8_wstring() to work here, so we'll just
    // do similar work with the byte count, which calculates the required
    // amount of bytes for a sequence. The following sequences represent the
    // various utf8 boundaries, i.e., their maximum values before needing an
    // extra byte etc.
    assert(utf8_bytecnt_unicode((val[0] = 0xd800, val[1] = 0xdc00, val), 2) == 1);
    assert(utf8_bytecnt_unicode((val[0] = 0xd801, val[1] = 0xdc00, val), 2) == 2);
    assert(utf8_bytecnt_unicode((val[0] = 0xd802, val[1] = 0xdc00, val), 2) == 3);
    assert(utf8_bytecnt_unicode((val[0] = 0xd840, val[1] = 0xdc00, val), 2) == 4);

    // We used to have some issues with signed chars and the MSB being set as
    // we wouldn't cast these as unsigned characters. This would result in
    // utf8_length(0xffffff81) returning -1, rather than utf8_length(0x81)
    // returning 2. Similarly to incorrect return values of utf8_length() we'd
    // also experience out-of-bounds writes as our buffer would be indexed by
    // -1, resulting in undefined behavior.
    assert(utf8_bytecnt_ascii("\x81", 1) == 2);
    assert(utf8_bytecnt_unicode(L"\u8081", 1) == 3);
    assert(memcmp(utf8_string("\x81", 1), "\x02\x00\x00\x00\xc2\x81", 6) == 0);
    assert(memcmp(utf8_wstring(L"\u8081", 1), "\x03\x00\x00\x00\xe8\x82\x81", 7) == 0);
    pipe("INFO:Test finished!");
    return 0;
}
