/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2015 Cuckoo Foundation.

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

#include <stdio.h>
#include <windows.h>
#include "../inc/assembly.h"

#define INJECT_NONE 0
#define INJECT_CRT  1
#define INJECT_APC  2

#define DPRINT(fmt, ...) if(verbose != 0) fprintf(stderr, fmt, #__VA_ARGS__)

static int verbose = 0;

FARPROC resolve_symbol(const char *library, const char *funcname)
{
    FARPROC ret = GetProcAddress(LoadLibrary(library), funcname);
    if(ret == NULL) {
        fprintf(stderr, "[-] Error resolving %s!%s?!\n", library, funcname);
        exit(1);
    }

    return ret;
}

HANDLE open_process(uintptr_t pid)
{
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(process_handle == NULL) {
        fprintf(stderr, "[-] Error getting access to process: %ld!\n",
            GetLastError());
        exit(1);
    }

    return process_handle;
}

HANDLE open_thread(uintptr_t tid)
{
    HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if(process_handle == NULL) {
        fprintf(stderr, "[-] Error getting access to thread: %ld!\n",
            GetLastError());
        exit(1);
    }

    return thread_handle;
}

void read_data(uintptr_t pid, void *addr, void *data, uint32_t length)
{
    HANDLE process_handle = open_process(pid);

    DWORD_PTR bytes_read;
    if(ReadProcessMemory(process_handle, addr, data, length,
            &bytes_read) == FALSE || bytes_read != length) {
        fprintf(stderr, "[-] Error reading data from process: %ld\n",
            GetLastError());
        exit(1);
    }

    CloseHandle(process_handle);
}

void *write_data(uintptr_t pid, const void *data, uint32_t length)
{
    HANDLE process_handle = open_process(pid);

    void *addr = VirtualAllocEx(process_handle, NULL, length,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(addr == NULL) {
        fprintf(stderr, "[-] Error allocating memory in process: %ld!\n",
            GetLastError());
        exit(1);
    }

    DWORD_PTR bytes_written;
    if(WriteProcessMemory(process_handle, addr, data, length,
            &bytes_written) == FALSE || bytes_written != length) {
        fprintf(stderr, "[-] Error writing data to process: %ld\n",
            GetLastError());
        exit(1);
    }

    CloseHandle(process_handle);
    return addr;
}

void free_data(uintptr_t pid, void *addr, uint32_t length)
{
    HANDLE process_handle = open_process(pid);
    VirtualFreeEx(process_handle, addr, length, MEM_RELEASE);
    CloseHandle(process_handle);
}

uintptr_t create_thread_and_wait(uintptr_t pid, void *addr, void *arg)
{
    HANDLE process_handle = open_process(pid);

    HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0,
        (LPTHREAD_START_ROUTINE) addr, arg, 0, NULL);
    if(thread_handle == NULL) {
        fprintf(stderr, "[-] Error injecting remote thread in process: %ld\n",
            GetLastError());
        exit(1);
    }

    WaitForSingleObject(thread_handle, INFINITE);

    INT32 exit_code;
    GetExitCodeThread(thread_handle, &exit_code);

    CloseHandle(thread_handle);
    CloseHandle(process_handle);

    return exit_code;
}

uintptr_t start_app(uintptr_t from, const char *path, const char *cmd_line,
    uintptr_t *tid)
{
    STARTUPINFO si; PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    // Emulate explorer.exe's startupinfo flags behavior.
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;

    FARPROC create_process_a = resolve_symbol("kernel32", "CreateProcessA");
    FARPROC close_handle = resolve_symbol("kernel32", "CloseHandle");
    FARPROC get_last_error = resolve_symbol("kernel32", "GetLastError");

    void *path_addr = write_data(from, path, strlen(path) + 1);
    void *cmd_addr = write_data(from, cmd_line, strlen(cmd_line) + 1);
    void *si_addr = write_data(from, &si, sizeof(si));
    void *pi_addr = write_data(from, &pi, sizeof(pi));

    const char *temp_dir = getenv("TEMP"); void *temp_addr = NULL;
    if(temp_dir != NULL) {
        temp_addr = write_data(from, temp_dir, strlen(temp_dir) + 1);
    }

    char shellcode[512]; char *ptr = shellcode;

    ptr += asm_pushv(ptr, pi_addr);
    ptr += asm_pushv(ptr, si_addr);
    ptr += asm_pushv(ptr, temp_addr);
    ptr += asm_pushv(ptr, NULL);
    ptr += asm_push(ptr, CREATE_NEW_CONSOLE | CREATE_SUSPENDED);
    ptr += asm_push(ptr, TRUE);

#if __x86_64__
    ptr += asm_move_regimmv(ptr, R_R9, NULL);
    ptr += asm_move_regimmv(ptr, R_R8, NULL);
    ptr += asm_move_regimmv(ptr, R_RDX, cmd_addr);
    ptr += asm_move_regimmv(ptr, R_RCX, path_addr);
#else
    ptr += asm_pushv(ptr, NULL);
    ptr += asm_pushv(ptr, NULL);
    ptr += asm_pushv(ptr, cmd_addr);
    ptr += asm_pushv(ptr, path_addr);
#endif

    ptr += asm_call(ptr, create_process_a);

    ptr += asm_call(ptr, get_last_error);
    ptr += asm_return(ptr, 4);

    void *shellcode_addr = write_data(from, shellcode, ptr - shellcode);

    uintptr_t last_error = create_thread_and_wait(from, shellcode_addr, NULL);
    if(last_error != 0) {
        fprintf(stderr, "[-] Error launching process: %ld & %ld!\n",
            GetLastError(), last_error);
        exit(1);
    }

    read_data(from, pi_addr, &pi, sizeof(pi));

    free_data(from, pi_addr, sizeof(pi));
    free_data(from, si_addr, sizeof(si));
    free_data(from, temp_addr, strlen(temp_dir) + 1);
    free_data(from, cmd_addr, strlen(cmd_line) + 1);
    free_data(from, path_addr, strlen(path) + 1);
    free_data(from, shellcode_addr, ptr - shellcode);

    ptr = shellcode;

#if __x86_64__
    ptr += asm_move_regimmv(ptr, R_RCX, pi.hThread);
#else
    ptr += asm_pushv(ptr, pi.hThread);
#endif
    ptr += asm_call(ptr, close_handle);

#if __x86_64__
    ptr += asm_move_regimmv(ptr, R_RCX, pi.hProcess);
#else
    ptr += asm_pushv(ptr, pi.hProcess);
#endif

    ptr += asm_call(ptr, close_handle);
    ptr += asm_return(ptr, 4);

    shellcode_addr = write_data(from, shellcode, ptr - shellcode);
    create_thread_and_wait(from, shellcode_addr, NULL);

    if(tid != NULL) {
        *tid = pi.dwThreadId;
    }
    return pi.dwProcessId;
}

void load_dll_crt(uintptr_t pid, const char *dll_path)
{
    FARPROC load_library_a = resolve_symbol("kernel32", "LoadLibraryA");

    void *dll_addr = write_data(pid, dll_path, strlen(dll_path) + 1);

    char shellcode[128]; char *ptr = shellcode;

    ptr += asm_pushv(ptr, dll_addr);
    ptr += asm_call(ptr, load_library_a);
    ptr += asm_call(ptr, get_last_error);
    ptr += asm_return(ptr, 4);

    void *shellcode_addr = write_data(pid, shellcode, ptr - shellcode);

    // Run LoadLibraryA(dll_path) in the target process.
    uintptr_t last_error = create_thread_and_wait(pid, shellcode_addr, NULL);
    if(last_error != 0) {
        fprintf(stderr, "[-] Error loading monitor into process: %ld & %ld\n",
            GetLastError(), last_error);
        exit(1);
    }

    free_data(dll_addr);
}

void load_dll_apc(uintptr_t pid, uintptr_t tid, const char *dll_path)
{
    HANDLE thread_handle = open_thread(tid);
    FARPROC load_library_a = resolve_symbol("kernel32", "LoadLibraryA");

    void *dll_addr = write_data(pid, dll_path, strlen(dll_path) + 1);

    // Add LoadLibraryA(dll_path) to the APC queue.
    if(QueueUserAPC((PAPCFUNC) load_library_a, thread_handle,
            (ULONG_PTR) dll_addr) == 0) {
        fprintf(stderr, "[-] Error adding task to APC queue: %ld\n",
            GetLastError());
        exit(1);
    }

    // TODO Come up with a way to deallocate dll_addr.
    CloseHandle(thread_handle);
}

void resume_thread(uintptr_t tid)
{
    HANDLE thread_handle = open_thread(tid);
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
}

void grant_debug_privileges(uintptr_t pid)
{
    HANDLE token_handle, process_handle = open_process(pid);

    if(OpenProcessToken(process_handle, TOKEN_ALL_ACCESS,
            &token_handle) == 0) {
        fprintf(stderr, "[-] Error obtaining process token: %ld\n",
            GetLastError());
        exit(1);
    }

    LUID original_luid;
    if(LookupPrivilegeValue(NULL, "SeDebugPrivilege", &original_luid) == 0) {
        fprintf(stderr, "[-] Error obtaining original luid: %ld\n",
            GetLastError());
        exit(1);
    }

    LUID_AND_ATTRIBUTES luid_attr;
    luid_attr.Luid = original_luid;
    luid_attr.Attributes = SE_PRIVILEGE_ENABLED;

    TOKEN_PRIVILEGES token_privileges;
    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges = &luid_attr;

    if(AdjustTokenPrivileges(token_handle, FALSE, &token_privileges, 0, NULL,
            NULL) == 0) {
        fprintf(stderr, "[-] Error adjusting token privileges: %ld\n",
            GetLastError());
        exit(1);
    }

    CloseHandle(token_handle);
    CloseHandle(process_handle);
}

uintptr_t pid_from_process_name(const char *process_name)
{
    PROCESSENTRY32 row; HANDLE snapshot_handle;

    snapshot_handle = CreateToolhelp32Snapshot(0, 0);
    if(snapshot_handle == NULL) {
        fprintf(stderr, "[-] Error obtaining snapshot handle: %ld\n",
            GetLastError());
        exit(1);
    }

    if(Process32First(snapshot_handle, &row) == FALSE) {
        fprintf(stderr, "[-] Error enumerating the first process: %ld\n",
            GetLastError());
        exit(1);
    }

    do {
        if(stricmp(row.szExeFile, process_name) == 0) {
            CloseHandle(snapshot_handle);
            return row.th32ProcessID;
        }
    } while (Process32Next(snapshot_handle, &row) != FALSE);

    CloseHandle(snapshot_handle);

    fprintf(stderr, "[-] Error finding process by name: %s\n", process_name);
    exit(1);
}

int main(int argc, char *argv[])
{
    if(argc < 4) {
        printf("Usage: %s <options..>\n", argv[0]);
        printf("Options:\n");
        printf("  --crt                  CreateRemoteThread injection\n");
        printf("  --apc                  QueueUserAPC injection\n");
        printf("  --dll <dll>            DLL to inject\n");
        printf("  --app <app>            Path to application to start\n");
        printf("  --cmdline <cmd>        Cmdline string\n");
        printf("  --pid <pid>            Process identifier to inject\n");
        printf("  --tid <tid>            Thread identifier to inject\n");
        printf("  --from <pid>           Inject from another process\n");
        printf("  --from-process <name>  "
            "Inject from another process, resolves pid\n");
        printf("  --config <path>        "
            "Configuration file for the monitor\n");
        printf("  --verbose              Verbose switch\n");
        return 1;
    }

    const char *dll_path = NULL, *app_path = NULL, *cmd_line = NULL;
    const char *config_file = NULL, *from_process = NULL;
    uintptr_t pid = 0, tid = 0, from = 0, inj_mode = INJECT_NONE;

    for (int idx = 1; idx < argc; idx++) {
        if(strcmp(argv[idx], "--crt") == 0) {
            inj_mode = INJECT_CRT;
            continue;
        }

        if(strcmp(argv[idx], "--apc") == 0) {
            inj_mode = INJECT_APC;
            continue;
        }

        if(strcmp(argv[idx], "--dll") == 0) {
            dll_path = argv[++idx];
            continue;
        }

        if(strcmp(argv[idx], "--app") == 0) {
            app_path = argv[++idx];
            continue;
        }

        if(strcmp(argv[idx], "--cmdline") == 0) {
            cmd_line = argv[++idx];
            continue;
        }

        if(strcmp(argv[idx], "--pid") == 0) {
            pid = strtoul(argv[++idx], NULL, 10);
            continue;
        }

        if(strcmp(argv[idx], "--tid") == 0) {
            tid = strtoul(argv[++idx], NULL, 10);
            continue;
        }

        if(strcmp(argv[idx], "--from") == 0) {
            from = strtoul(argv[++idx], NULL, 10);
            continue;
        }

        if(strcmp(argv[idx], "--from-process") == 0) {
            from_process = argv[++idx];
            continue;
        }

        if(strcmp(argv[idx], "--config") == 0) {
            config_file = argv[++idx];
            continue;
        }

        if(strcmp(argv[idx], "--verbose") == 0) {
            verbose = 1;
            continue;
        }
    }

    if(inj_mode == INJECT_NONE) {
        fprintf(stderr, "[-] No injection method has been provided!\n");
        return 1;
    }

    if(inj_mode == INJECT_CRT && pid == 0 && app_path == NULL) {
        fprintf(stderr, "[-] No injection target has been provided!\n");
        return 1;
    }

    if(inj_mode == INJECT_APC && tid == 0 && app_path == NULL) {
        fprintf(stderr, "[-] No injection target has been provided!\n");
        return 1;
    }

    OFSTRUCT of; memset(&of, 0, sizeof(of)); of.cBytes = sizeof(of);
    if(OpenFile(dll_path, &of, OF_EXIST) == HFILE_ERROR) {
        fprintf(stderr, "[-] DLL file does not exist!\n");
        return 1;
    }

    if(from != 0 && from_process != NULL) {
        fprintf(stderr, "[-] Both --from and --from-process are specified\n");
        return 1;
    }

    if(from_process != NULL) {
        from = pid_from_process_name(from_process);
    }

    grant_debug_privileges(GetCurrentProcessId());

    if(app_path != NULL) {
        // If no source process has been specified, then we use our
        // own process.
        if(from == 0) {
            DPRINTF("[x] Starting process from our own process\n");
            from = GetCurrentProcessId();
        }

        if(cmd_line == NULL) {
            DPRINTF("[x] No cmdline provided, using app path.\n");
            cmd_line = app_path;
        }

        pid = start_app(from, app_path, cmd_line, &tid);
    }

    // Drop the configuration file if available.
    if(config_file != NULL) {
        char filepath[MAX_PATH];

        sprintf(filepath, "C:\\cuckoo_%ld.ini", pid);
        if(MoveFile(config_file, filepath) == FALSE) {
            fprintf(stderr, "[-] Error dropping configuration file: %ld\n",
                GetLastError());
            return 1;
        }
    }

    switch (inj_mode) {
    case INJECT_CRT:
        load_dll_crt(pid, dll_path);
        break;

    case INJECT_APC:
        load_dll_apc(pid, tid, dll_path);
        break;

    default:
        fprintf(stderr, "[-] Unhandled injection mode: %d\n", inj_mode);
        return 1;
    }

    DPRINTF("[+] Injected successfully!\n");

    if(dbg_path != NULL) {
        char buf[1024];
        sprintf(buf, "\"%s\" -p %ld", dbg_path, pid);

        start_app(GetCurrentProcessId(), dbg_path, buf, NULL);

        Sleep(5000);
    }

    if(app_path != NULL && tid != 0) {
        resume_thread(tid);
    }

    // Report the process identifier.
    printf("%d", pid);
    return 0;
}
