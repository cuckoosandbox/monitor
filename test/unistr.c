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

// This program tests a fixed bug in the way that ascii and unicode strings
// are handled under Windows. Namely, when we use pipe() inside a hook, it
// will connect to a pipe server. To do this, a filename is required. Earlier
// we would pass an ascii string to CallNamedPipe(). However, due to the
// per-thread unicode string that Windows uses in order to convert from ascii
// to unicode, the existing unicode string would be overwritten to convert our
// pipe server filename to unicode. For hook handlers that would be given such
// a unicode string, and where we would use pipe(), the unicode string would
// thus be overwritten, resulting in incorrect logic.
//
// This program basically tests this behavior. The file a.txt is created and
// should thus be deletable. However, if the unicode string a.txt is
// overwritten with our pipe filename, then we won't be able to delete it, as
// you can't delete a pipe name, and thus the DeleteFile() function will fail.
//
// Note that this test will return success if a DeleteFileA hook is present,
// rather than just a DeleteFileW hook.
//
// This bug has been fixed by using a unicode string filename together with
// CallNamedPipeW().

/// FINISH= yes
/// PIPE= yes

#include <stdio.h>
#include <winsock2.h>
#include "pipe.h"

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

    fclose(fopen("a.txt", "wb"));
    assert(DeleteFile("a.txt") == TRUE);
    pipe("INFO:Test finished!");
    return 0;
}
