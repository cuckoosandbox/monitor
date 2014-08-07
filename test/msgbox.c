#include <stdio.h>
#include <windows.h>

int main()
{
    HMODULE module; FARPROC m_monitor_init, m_monitor_hook;

#if __x86_64__
    module = LoadLibrary("monitor-x64.dll");
#else
    module = LoadLibrary("monitor-x86.dll");
#endif

    m_monitor_init = GetProcAddress(module, "monitor_init");
    m_monitor_hook = GetProcAddress(module, "monitor_hook");

    m_monitor_init(module);
    m_monitor_hook();

    MessageBox(NULL, "Hello", "World", 0);
}
