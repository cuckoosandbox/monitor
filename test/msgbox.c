#include <stdio.h>
#include <windows.h>

#if __x86_64__
#define MONITOR_DLL "monitor-x64.dll"
#else
#define MONITOR_DLL "monitor-x86.dll"
#endif

int main()
{
    LoadLibrary(MONITOR_DLL);

    MessageBox(NULL, "Hello", "World", 0);
}
