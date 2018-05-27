/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2018 Cuckoo Foundation.

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

#include <windows.h>
#include "pipe.h"

// Tests sleep skipping support.

/// FINISH= yes
/// PIPE= yes

int main()
{
    pipe_init("\\\\.\\PIPE\\cuckoo", 0);
    Sleep(5000);
    pipe("INFO:Test finished!");
    return 0;
}
