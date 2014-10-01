#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "hooking.h"

int WINAPI b(int x)
{
    int addr;
    printf("in b.. 0x%p\n", &addr);
    return 3 + 4 + x;
}

int WINAPI a(int x)
{
    int addr;
    printf("in a.. 0x%p\n", &addr);
    return b(5 + x);
}

int (WINAPI *old_a)(int x);
int (WINAPI *old_b)(int x);

int WINAPI new_a(int x)
{
    printf("a-x: %d, &x: 0x%p\n", x, &x);
    int ret = old_a(x);
    printf("a-y: %d, &x: 0x%p\n", ret, &x);
    return ret;
}

int WINAPI new_b(int x)
{
    printf("b-x: %d, &x: 0x%p\n", x, &x);
    int ret = old_b(x);
    printf("b-y: %d, &x: 0x%p\n", ret, &x);
    return ret;
}

static uint32_t get_edi()
{
    uint32_t value;
    __asm__ __volatile__("movl %%edi, %0" : "=r" (value));
    return value;
}

static void set_edi(uint32_t value)
{
    __asm__ __volatile__("movl %0, %%edi" :: "m" (value));
}

int main()
{
    HMODULE module; FARPROC m_monitor_init, m_hook2;

    module = LoadLibrary("monitor.dll");
    m_monitor_init = GetProcAddress(module, "monitor_init");
    m_hook2 = GetProcAddress(module, "hook2");

    m_monitor_init(module);

    set_edi(0x41414141);
    printf("before-hook   a(1..3): %d %d %d\n", a(1), a(2), a(3));
    printf("-> %x %x %x\n", get_edi(), get_edi(), get_edi());

    hook_t hk_a = {
        NULL, "a", (FARPROC) &new_a, (FARPROC *) &old_a, 0,
        (uint8_t *) &a, 0, NULL
    };

    hook_t hk_b = {
        NULL, "b", (FARPROC) &new_b, (FARPROC *) &old_b, 0,
        (uint8_t *) &b, 0, NULL
    };

    m_hook2(&hk_a);

    set_edi(0x42424242);
    printf("after-hook-a  a(1..3): %d %d %d\n", a(1), a(2), a(3));
    printf("-> %x %x %x\n", get_edi(), get_edi(), get_edi());

    m_hook2(&hk_b);

    set_edi(0x43434343);
    printf("after-hook-b  a(1..3): %d %d %d\n", a(1), a(2), a(3));
    printf("-> %x %x %x\n", get_edi(), get_edi(), get_edi());
}
