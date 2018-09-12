/* To compile: cl.exe bypass_um_hooks.c user32.lib */
#include <stdio.h>
#include <windows.h>

#define CAPTION "Bypass UM Hook"
typedef unsigned char uint8_t;

void main()
{
    uint8_t *func = (uint8_t*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenThread");
    uint8_t buffer[10] = { 0 };
    SIZE_T read;
    DWORD oldprotect = 0;
    
    if (func == NULL)
    {
        MessageBoxA(NULL, "Failed to resolve NtOpenThread", CAPTION, MB_OK);
        return;
    }

    // The VirtualProtect call should not be able to modify the target address to WRITE
    if (!VirtualProtect(func, 0x10, PAGE_EXECUTE_READWRITE, &oldprotect))
    {
        MessageBoxA(NULL, "Failed to modify protection", CAPTION, MB_OK);
        return;
    }

    ReadProcessMemory(GetCurrentProcess(), func, buffer, sizeof(buffer), &read);
    
    // Simulate the malware's behavior attempting to detect the UM's hooks and then restore the hooked instructions
    // Found PUSH xxxxx opcode
    if (buffer[0] == 0x68 || buffer[0] == 0xe9)
    {
        // With the UM hooks protection enabled, it should trigger AV as the target address does not have write permission
        *func = 0xb8;
    }

    // The UM hook protection should skip the AV above and proceed its main payload
    // In other words,
    // Protection enabled: Observed message box prompt
    // Protection disabled: No message box will be prompted
    MessageBoxA(NULL, "Done", CAPTION, MB_OK);
}