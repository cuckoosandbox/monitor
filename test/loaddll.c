/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2017 Cuckoo Foundation.

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

// This unittest demonstrates that Cuckoo logs too many API calls when doing
// a simple LoadLibrary() on Windows-specific DLLs. In the future we should be
// checking against the list of Known DLLs to avoid logging lots of
// unnecessary API calls.

/// OBJECTS=

#include <windows.h>

int main()
{
    LoadLibrary("shell32");
}
