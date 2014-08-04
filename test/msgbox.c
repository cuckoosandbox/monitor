#include <stdio.h>
#include <windows.h>

int main()
{
    HMODULE module; FARPROC m_monitor_init, m_monitor_hook;

    module = LoadLibrary("monitor.dll");
    m_monitor_init = GetProcAddress(module, "monitor_init");
    m_monitor_hook = GetProcAddress(module, "monitor_hook");

    m_monitor_init(module);
    m_monitor_hook();

    MessageBox(NULL, "Hello", "World", 0);
}
