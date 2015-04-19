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
#include <inttypes.h>
#include <windows.h>
#include <tlhelp32.h>
#include "../inc/assembly.h"

#define INJECT_NONE 0
#define INJECT_CRT  1
#define INJECT_APC  2
#define INJECT_FREE 3

#define DPRINTF(fmt, ...) if(verbose != 0) fprintf(stderr, fmt, ##__VA_ARGS__)

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

HANDLE open_process(uint32_t pid)
{
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(process_handle == NULL) {
        fprintf(stderr, "[-] Error getting access to process: %ld!\n",
            GetLastError());
        exit(1);
    }

    return process_handle;
}

HANDLE open_thread(uint32_t tid)
{
    HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if(thread_handle == NULL) {
        fprintf(stderr, "[-] Error getting access to thread: %ld!\n",
            GetLastError());
        exit(1);
    }

    return thread_handle;
}

void read_data(uint32_t pid, void *addr, void *data, uint32_t length)
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

void *write_data(uint32_t pid, const void *data, uint32_t length)
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

void free_data(uint32_t pid, void *addr, uint32_t length)
{
    if(addr != NULL && length != 0) {
        HANDLE process_handle = open_process(pid);
        VirtualFreeEx(process_handle, addr, length, MEM_RELEASE);
        CloseHandle(process_handle);
    }
}

uint32_t create_thread_and_wait(uint32_t pid, void *addr, void *arg)
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

    DWORD exit_code;
    GetExitCodeThread(thread_handle, &exit_code);

    CloseHandle(thread_handle);
    CloseHandle(process_handle);

    return exit_code;
}

uint32_t start_app(uint32_t from, const char *path, const char *cmd_line,
    const char *curdir, uint32_t *tid)
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

    // If not provided, default to $TEMP.
    if(curdir == NULL) {
        curdir = getenv("TEMP");
    }

    void *curdir_addr = write_data(from, curdir, strlen(curdir) + 1);

    uint8_t shellcode[512]; uint8_t *ptr = shellcode;

    ptr += asm_pushv(ptr, pi_addr);
    ptr += asm_pushv(ptr, si_addr);
    ptr += asm_pushv(ptr, curdir_addr);
    ptr += asm_pushv(ptr, NULL);
    ptr += asm_push(ptr, CREATE_NEW_CONSOLE | CREATE_SUSPENDED);
    ptr += asm_push(ptr, TRUE);

#if __x86_64__
    ptr += asm_move_regimmv(ptr, R_R9, NULL);
    ptr += asm_move_regimmv(ptr, R_R8, NULL);
    ptr += asm_move_regimmv(ptr, R_RDX, cmd_addr);
    ptr += asm_move_regimmv(ptr, R_RCX, path_addr);

    ptr += asm_pushv(ptr, NULL);
    ptr += asm_pushv(ptr, NULL);
    ptr += asm_pushv(ptr, NULL);
    ptr += asm_pushv(ptr, NULL);
#else
    ptr += asm_pushv(ptr, NULL);
    ptr += asm_pushv(ptr, NULL);
    ptr += asm_pushv(ptr, cmd_addr);
    ptr += asm_pushv(ptr, path_addr);
#endif

    ptr += asm_call(ptr, create_process_a);

#if __x86_64__
    ptr += asm_add_regimm(ptr, R_RSP, 10 * sizeof(uintptr_t));
#endif

    // If the return value of CreateProcessA was FALSE, then we return the
    // GetLastError(), otherwise we return zero.
#if __x86_64__
    ptr += asm_jregz(ptr, R_RAX, ASM_MOVE_REGIMM_SIZE + ASM_RETURN_SIZE);
    ptr += asm_move_regimm(ptr, R_RAX, 0);
    ptr += asm_return(ptr, 0);
#else
    ptr += asm_jregz(ptr, R_EAX, ASM_MOVE_REGIMM_SIZE + ASM_RETURN_SIZE);
    ptr += asm_move_regimm(ptr, R_EAX, 0);
    ptr += asm_return(ptr, 4);
#endif

    ptr += asm_call(ptr, get_last_error);

#if __x86_64__
    ptr += asm_return(ptr, 0);
#else
    ptr += asm_return(ptr, 4);
#endif

    void *shellcode_addr = write_data(from, shellcode, ptr - shellcode);

    uint32_t last_error = create_thread_and_wait(from, shellcode_addr, NULL);
    if(last_error != 0) {
        fprintf(stderr, "[-] Error launching process: %d\n", last_error);
        exit(1);
    }

    read_data(from, pi_addr, &pi, sizeof(pi));

    free_data(from, pi_addr, sizeof(pi));
    free_data(from, si_addr, sizeof(si));
    free_data(from, curdir_addr, strlen(curdir) + 1);
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
#if __x86_64__
    ptr += asm_return(ptr, 0);
#else
    ptr += asm_return(ptr, 4);
#endif

    shellcode_addr = write_data(from, shellcode, ptr - shellcode);
    create_thread_and_wait(from, shellcode_addr, NULL);

    free_data(from, shellcode_addr, ptr - shellcode);

    if(tid != NULL) {
        *tid = pi.dwThreadId;
    }
    return pi.dwProcessId;
}

void load_dll_crt(uint32_t pid, const char *dll_path)
{
    FARPROC load_library_a = resolve_symbol("kernel32", "LoadLibraryA");
    FARPROC get_last_error = resolve_symbol("kernel32", "GetLastError");

    void *dll_addr = write_data(pid, dll_path, strlen(dll_path) + 1);

    uint8_t shellcode[128]; uint8_t *ptr = shellcode;

#if __x86_64__
    ptr += asm_move_regimmv(ptr, R_RCX, dll_addr);
#else
    ptr += asm_pushv(ptr, dll_addr);
#endif

    ptr += asm_call(ptr, load_library_a);
    ptr += asm_call(ptr, get_last_error);

#if __x86_64__
    ptr += asm_return(ptr, 0);
#else
    ptr += asm_return(ptr, 4);
#endif

    void *shellcode_addr = write_data(pid, shellcode, ptr - shellcode);

    // Run LoadLibraryA(dll_path) in the target process.
    uint32_t last_error = create_thread_and_wait(pid, shellcode_addr, NULL);
    if(last_error != 0) {
        fprintf(stderr, "[-] Error loading monitor into process: %d\n",
            last_error);
        exit(1);
    }

    free_data(pid, dll_addr, strlen(dll_path) + 1);
    free_data(pid, shellcode_addr, ptr - shellcode);
}

void load_dll_apc(uint32_t pid, uint32_t tid, const char *dll_path)
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

void resume_thread(uint32_t tid)
{
    HANDLE thread_handle = open_thread(tid);
    ResumeThread(thread_handle);
    CloseHandle(thread_handle);
}

void grant_debug_privileges(uint32_t pid)
{
    HANDLE token_handle, process_handle = open_process(pid);

    if(OpenProcessToken(process_handle, TOKEN_ALL_ACCESS,
            &token_handle) == 0) {
        fprintf(stderr, "[-] Error obtaining process token: %ld\n",
            GetLastError());
        exit(1);
    }

    LUID original_luid;
    if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &original_luid) == 0) {
        fprintf(stderr, "[-] Error obtaining original luid: %ld\n",
            GetLastError());
        exit(1);
    }

    TOKEN_PRIVILEGES token_privileges;
    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges[0].Luid = original_luid;
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if(AdjustTokenPrivileges(token_handle, FALSE, &token_privileges, 0, NULL,
            NULL) == 0) {
        fprintf(stderr, "[-] Error adjusting token privileges: %ld\n",
            GetLastError());
        exit(1);
    }

    CloseHandle(token_handle);
    CloseHandle(process_handle);
}

uint32_t pid_from_process_name(const char *process_name)
{
    PROCESSENTRY32 row; HANDLE snapshot_handle;

    snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snapshot_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Error obtaining snapshot handle: %ld\n",
            GetLastError());
        exit(1);
    }

    row.dwSize = sizeof(row);
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
        printf("  --free                 Do not inject our monitor\n");
        printf("  --dll <dll>            DLL to inject\n");
        printf("  --app <app>            Path to application to start\n");
        printf("  --cmdline <cmd>        Cmdline string\n");
        printf("  --curdir <dirpath>     Current working directory\n");
        printf("  --pid <pid>            Process identifier to inject\n");
        printf("  --tid <tid>            Thread identifier to inject\n");
        printf("  --from <pid>           Inject from another process\n");
        printf("  --from-process <name>  "
            "Inject from another process, resolves pid\n");
        printf("  --config <path>        "
            "Configuration file for the monitor\n");
        printf("  --dbg <path>           "
            "Attach debugger to target process\n");
        printf("  --verbose              Verbose switch\n");
        return 1;
    }

    const char *dll_path = NULL, *app_path = NULL, *cmd_line = NULL;
    const char *config_file = NULL, *from_process = NULL, *dbg_path = NULL;
    const char *curdir = NULL;
    uint32_t pid = 0, tid = 0, from = 0, inj_mode = INJECT_NONE;

    for (int idx = 1; idx < argc; idx++) {
        if(strcmp(argv[idx], "--crt") == 0) {
            inj_mode = INJECT_CRT;
            continue;
        }

        if(strcmp(argv[idx], "--apc") == 0) {
            inj_mode = INJECT_APC;
            continue;
        }

        if(strcmp(argv[idx], "--free") == 0) {
            inj_mode = INJECT_FREE;
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

        if(strcmp(argv[idx], "--curdir") == 0) {
            curdir = argv[++idx];
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

        if(strcmp(argv[idx], "--dbg") == 0) {
            dbg_path = argv[++idx];
            continue;
        }

        if(strcmp(argv[idx], "--verbose") == 0) {
            verbose = 1;
            continue;
        }

        fprintf(stderr, "[-] Found unsupported argument: %s\n", argv[idx]);
        return 1;
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

    if(inj_mode == INJECT_FREE && app_path == NULL) {
        fprintf(stderr, "[-] An app path is required when not injecting!\n");
        return 1;
    }

    OFSTRUCT of; memset(&of, 0, sizeof(of)); of.cBytes = sizeof(of);
    char dllpath[MAX_PATH];

    if(inj_mode == INJECT_FREE) {
        if(dll_path != NULL || tid != 0 || pid != 0) {
            fprintf(stderr,
                "[-] Unused --tid/--pid/--dll provided in --free mode!\n");
            return 1;
        }
    }

    if(inj_mode != INJECT_FREE) {
        if(OpenFile(dll_path, &of, OF_EXIST) == HFILE_ERROR) {
            fprintf(stderr, "[-] Invalid DLL filepath has been provided\n");
            return 1;
        }

        if(GetFullPathName(dll_path, MAX_PATH, dllpath, NULL) == 0) {
            fprintf(stderr, "[-] Invalid DLL filepath has been provided\n");
            return 1;
        }
    }

    if(from != 0 && from_process != NULL) {
        fprintf(stderr, "[-] Both --from and --from-process are specified\n");
        return 1;
    }

    grant_debug_privileges(GetCurrentProcessId());

    if(app_path != NULL) {
        // If a process name has been provided as source process, then find
        // its process identifier (or first, if multiple).
        if(from_process != NULL) {
            from = pid_from_process_name(from_process);
        }

        // If no source process has been specified, then we use our
        // own process.
        if(from == 0) {
            DPRINTF("[x] Starting process from our own process\n");
            from = GetCurrentProcessId();
        }

        if(OpenFile(app_path, &of, OF_EXIST) == HFILE_ERROR) {
            fprintf(stderr, "[-] Invalid app filepath has been provided\n");
            return 1;
        }

        // Get the full path as the other process probably doesn't have the same
        // working directory.
        char filepath[MAX_PATH];
        if(GetFullPathName(app_path, MAX_PATH, filepath, NULL) == 0) {
            fprintf(stderr, "[-] Invalid app filepath has been provided\n");
            return 1;
        }

        if(cmd_line == NULL) {
            DPRINTF("[x] No cmdline provided, using app path.\n");
            cmd_line = filepath;
        }

        pid = start_app(from, filepath, cmd_line, curdir, &tid);
    }

    // Drop the configuration file if available.
    if(config_file != NULL) {
        char filepath[MAX_PATH];

        sprintf(filepath, "C:\\cuckoo_%d.ini", pid);
        if(MoveFile(config_file, filepath) == FALSE) {
            fprintf(stderr, "[-] Error dropping configuration file: %ld\n",
                GetLastError());
            return 1;
        }
    }

    switch (inj_mode) {
    case INJECT_CRT:
        load_dll_crt(pid, dllpath);
        break;

    case INJECT_APC:
        load_dll_apc(pid, tid, dllpath);
        break;

    case INJECT_FREE:
        break;

    default:
        fprintf(stderr, "[-] Unhandled injection mode: %d\n", inj_mode);
        return 1;
    }

    DPRINTF("[+] Injected successfully!\n");

    if(dbg_path != NULL) {
        char buf[1024];
        sprintf(buf, "\"%s\" -p %d", dbg_path, pid);

        start_app(GetCurrentProcessId(), dbg_path, buf, NULL, NULL);

        Sleep(5000);
    }

    if(app_path != NULL && tid != 0) {
        resume_thread(tid);
    }

    // Report the process identifier.
    printf("%d", pid);
    return 0;
}
