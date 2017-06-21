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
#include <wchar.h>
#include <inttypes.h>
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include "../inc/ntapi.h"

#define INJECT_NONE 0
#define INJECT_CRT  1
#define INJECT_APC  2
#define INJECT_FREE 3

#define MAX_PATH_W 0x7fff
#define NOINLINE __attribute__((noinline))

typedef struct _dump_t {
    uint64_t addr;
    uint32_t size;
    uint32_t state;
    uint32_t type;
    uint32_t protect;
} dump_t;

static int verbose = 0;

void error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    exit(1);
}

uint32_t strsizeW(const wchar_t *s)
{
    return (lstrlenW(s) + 1) * sizeof(wchar_t);
}

FARPROC resolve_symbol(const char *library, const char *funcname)
{
    FARPROC ret = GetProcAddress(LoadLibrary(library), funcname);
    if(ret == NULL) {
        error("[-] Error resolving %s!%s?!\n", library, funcname);
    }

    return ret;
}

HANDLE open_process(uint32_t pid)
{
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(process_handle == NULL) {
        error("[-] Error getting access to process: %ld!\n", GetLastError());
    }

    return process_handle;
}

HANDLE open_thread(uint32_t tid)
{
    HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if(thread_handle == NULL) {
        error("[-] Error getting access to thread: %ld!\n", GetLastError());
    }

    return thread_handle;
}

void read_data(uint32_t pid, void *addr, void *data, uint32_t length)
{
    HANDLE process_handle = open_process(pid);

    DWORD_PTR bytes_read;
    if(ReadProcessMemory(process_handle, addr, data, length,
            &bytes_read) == FALSE || bytes_read != length) {
        error("[-] Error reading data from process: %ld\n", GetLastError());
    }

    CloseHandle(process_handle);
}

void *write_data(uint32_t pid, const void *data, uint32_t length)
{
    HANDLE process_handle = open_process(pid);

    void *addr = VirtualAllocEx(process_handle, NULL, length,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(addr == NULL) {
        error("[-] Error allocating memory in process: %ld!\n",
            GetLastError());
    }

    DWORD_PTR bytes_written;
    if(WriteProcessMemory(process_handle, addr, data, length,
            &bytes_written) == FALSE || bytes_written != length) {
        error("[-] Error writing data to process: %ld\n", GetLastError());
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

// Windows Vista and later have session restriction - a user-mode restriction
// to disallow injection into Windows services. The following toggles the
// restriction.
int toggle_session_restriction(int enable)
{
    static uint8_t origbuf[32];

    FARPROC p_csr_client_call_server =
        GetProcAddress(GetModuleHandle("ntdll"), "CsrClientCallServer");
    if(p_csr_client_call_server == NULL) {
        return -1;
    }

    // The following offsets are based on Brad Spengler's work after he
    // fixed up a working implementation in 64-bit mode - which apparently
    // was not yet publicly available. It seems that NtRequestWaitReplyPort
    // has to return success and that this return value is propagated into
    // offset 32 and 52 of the first argument, for 32-bit and 64-bit hosts,
    // respectively. The following two stubs do just that - spoof the
    // successful return value and put it at the right offset.

#if __x86_64__
    const unsigned char payload[] = {
        // xor eax, eax
        0x33, 0xc0,
        // mov dword [rcx+offset], eax
        0x89, 0x41, 0x34,
        // ret
        0xc3
    };
#else
    const unsigned char payload[] = {
        // xor eax, eax
        0x33, 0xc0,
        // mov ecx, [esp+4]
        0x8b, 0x4c, 0x24, 0x04,
        // mov dword [ecx+offset], eax
        0x89, 0x41, 0x20,
        // retn 0x10
        0xc2, 0x10, 0x00
    };
#endif

    unsigned long old_protect;
    if(VirtualProtect(p_csr_client_call_server, sizeof(payload),
            PAGE_EXECUTE_READWRITE, &old_protect) != FALSE) {

        if(enable == 0) {
            memcpy(origbuf, p_csr_client_call_server, sizeof(payload));
            memcpy(p_csr_client_call_server, payload, sizeof(payload));
        }
        else {
            memcpy(p_csr_client_call_server, origbuf, sizeof(payload));
        }

        VirtualProtect(p_csr_client_call_server, sizeof(payload),
            old_protect, &old_protect);
        return 0;
    }
    return -1;
}

uint32_t create_thread_and_wait(uint32_t pid, void *addr, void *arg)
{
    HANDLE process_handle = open_process(pid);

    HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0,
        (LPTHREAD_START_ROUTINE) addr, arg, 0, NULL);
    uint32_t return_value = GetLastError();
    if(thread_handle == NULL && return_value == ERROR_NOT_ENOUGH_MEMORY) {
        toggle_session_restriction(0);
        thread_handle = CreateRemoteThread(process_handle, NULL, 0,
            (LPTHREAD_START_ROUTINE) addr, arg, 0, NULL);
        return_value = GetLastError();
        toggle_session_restriction(1);
    }

    if(thread_handle == NULL) {
        error("[-] Error injecting remote thread in process: %d\n",
            return_value);
    }

    WaitForSingleObject(thread_handle, INFINITE);

    DWORD exit_code;
    GetExitCodeThread(thread_handle, &exit_code);

    CloseHandle(thread_handle);
    CloseHandle(process_handle);

    return exit_code;
}

typedef struct _create_process_t {
    FARPROC create_process_w;
    wchar_t *filepath;
    wchar_t *cmdline;
    wchar_t *curdir;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    FARPROC get_last_error;
} create_process_t;

uint32_t NOINLINE WINAPI create_process_worker(create_process_t *s)
{
    uint32_t ret = 0;

    if(s->create_process_w(s->filepath, s->cmdline, NULL, NULL, FALSE,
            CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, s->curdir,
            &s->si, &s->pi) == FALSE) {
        ret = s->get_last_error();
    }

    return ret;
}

uint32_t start_app(uint32_t from, const wchar_t *path,
    const wchar_t *arguments, const wchar_t *curdir, uint32_t *tid,
    int show_window)
{
    create_process_t s;
    memset(&s, 0, sizeof(s));

    s.si.cb = sizeof(s.si);

    // Emulate explorer.exe's startupinfo flags behavior.
    s.si.dwFlags = STARTF_USESHOWWINDOW;
    s.si.wShowWindow = show_window;

    s.create_process_w = resolve_symbol("kernel32", "CreateProcessW");
    s.get_last_error = resolve_symbol("kernel32", "GetLastError");

    wchar_t *cmd_line =
        malloc(strsizeW(path) + strsizeW(arguments) + 4 * sizeof(wchar_t));
    wsprintfW(cmd_line, L"\"%s\" %s", path, arguments);

    s.filepath = write_data(from, path, strsizeW(path));
    s.cmdline = write_data(from, cmd_line, strsizeW(cmd_line));
    s.curdir = write_data(from, curdir, strsizeW(curdir));

    create_process_t *settings_addr = write_data(from, &s, sizeof(s));

    void *shellcode_addr = write_data(from, &create_process_worker, 0x1000);

    uint32_t last_error =
        create_thread_and_wait(from, shellcode_addr, settings_addr);
    if(last_error != 0) {
        error("[-] Error launching process: %d\n", last_error);
    }

    read_data(from, settings_addr, &s, sizeof(s));

    free_data(from, s.curdir, strsizeW(curdir));
    free_data(from, s.cmdline, strsizeW(cmd_line));
    free_data(from, s.filepath, strsizeW(path));
    free_data(from, shellcode_addr, 0x1000);
    free_data(from, settings_addr, sizeof(s));
    free(cmd_line);

    HANDLE process_handle = open_process(from), object_handle;

    if(DuplicateHandle(process_handle, s.pi.hThread, GetCurrentProcess(),
            &object_handle, DUPLICATE_SAME_ACCESS, FALSE,
            DUPLICATE_CLOSE_SOURCE) != FALSE) {
        CloseHandle(object_handle);
    }

    if(DuplicateHandle(process_handle, s.pi.hProcess, GetCurrentProcess(),
            &object_handle, DUPLICATE_SAME_ACCESS, FALSE,
            DUPLICATE_CLOSE_SOURCE) != FALSE) {
        CloseHandle(object_handle);
    }

    CloseHandle(process_handle);

    if(tid != NULL) {
        *tid = s.pi.dwThreadId;
    }
    return s.pi.dwProcessId;
}

typedef struct _load_library_t {
    FARPROC ldr_load_dll;
    FARPROC get_last_error;
    UNICODE_STRING filepath;
} load_library_t;

uint32_t NOINLINE WINAPI load_library_worker(load_library_t *s)
{
    HMODULE module_handle; uint32_t ret = 0;
    if(NT_SUCCESS(s->ldr_load_dll(NULL, 0, &s->filepath,
            &module_handle)) == FALSE) {
        ret = s->get_last_error();
    }
    return ret;
}

void load_dll_crt(uint32_t pid, const wchar_t *dll_path)
{
    load_library_t s;
    memset(&s, 0, sizeof(s));

    s.ldr_load_dll = resolve_symbol("ntdll", "LdrLoadDll");
    s.get_last_error = resolve_symbol("ntdll", "RtlGetLastWin32Error");

    s.filepath.Length = lstrlenW(dll_path) * sizeof(wchar_t);
    s.filepath.MaximumLength = strsizeW(dll_path);
    s.filepath.Buffer = write_data(pid, dll_path, strsizeW(dll_path));

    void *settings_addr = write_data(pid, &s, sizeof(s));
    void *shellcode_addr = write_data(pid, &load_library_worker, 0x1000);

    // Run LdrLoadDll(..., dll_path, ...) in the target process.
    uint32_t last_error =
        create_thread_and_wait(pid, shellcode_addr, settings_addr);
    if(last_error != 0) {
        error("[-] Error loading monitor into process: %d\n", last_error);
    }

    free_data(pid, s.filepath.Buffer, strsizeW(dll_path));
    free_data(pid, settings_addr, sizeof(s));
    free_data(pid, shellcode_addr, 0x1000);
}

void load_dll_apc(uint32_t pid, uint32_t tid, const wchar_t *dll_path)
{
    load_library_t s;
    memset(&s, 0, sizeof(s));

    s.ldr_load_dll = resolve_symbol("ntdll", "LdrLoadDll");
    s.get_last_error = resolve_symbol("ntdll", "RtlGetLastWin32Error");

    s.filepath.Length = lstrlenW(dll_path) * sizeof(wchar_t);
    s.filepath.MaximumLength = strsizeW(dll_path);
    s.filepath.Buffer = write_data(pid, dll_path, strsizeW(dll_path));

    void *settings_addr = write_data(pid, &s, sizeof(s));
    void *shellcode_addr = write_data(pid, &load_library_worker, 0x1000);

    HANDLE thread_handle = open_thread(tid);

    // Add LdrLoadDll(..., dll_path, ...) to the APC queue.
    if(QueueUserAPC((PAPCFUNC) shellcode_addr, thread_handle,
            (ULONG_PTR) settings_addr) == 0) {
        error("[-] Error adding task to APC queue: %ld\n", GetLastError());
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
        error("[-] Error obtaining process token: %ld\n", GetLastError());
    }

    LUID original_luid;
    if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &original_luid) == 0) {
        error("[-] Error obtaining original luid: %ld\n", GetLastError());
    }

    TOKEN_PRIVILEGES token_privileges;
    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges[0].Luid = original_luid;
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if(AdjustTokenPrivileges(token_handle, FALSE, &token_privileges, 0, NULL,
            NULL) == 0) {
        error("[-] Error adjusting token privileges: %ld\n", GetLastError());
    }

    CloseHandle(token_handle);
    CloseHandle(process_handle);
}

uint32_t pid_from_process_name(const wchar_t *process_name)
{
    PROCESSENTRY32W row; HANDLE snapshot_handle;

    snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snapshot_handle == INVALID_HANDLE_VALUE) {
        error("[-] Error obtaining snapshot handle: %ld\n", GetLastError());
    }

    row.dwSize = sizeof(row);
    if(Process32FirstW(snapshot_handle, &row) == FALSE) {
        error("[-] Error enumerating the first process: %ld\n",
            GetLastError());
    }

    do {
        if(wcsicmp(row.szExeFile, process_name) == 0) {
            CloseHandle(snapshot_handle);
            return row.th32ProcessID;
        }
    } while (Process32NextW(snapshot_handle, &row) != FALSE);

    CloseHandle(snapshot_handle);

    error("[-] Error finding process by name: %S\n", process_name);
    return 0;
}

int dump(uint32_t pid, const wchar_t *filepath,
    uintptr_t addr, uint32_t length)
{
    SYSTEM_INFO si; MEMORY_BASIC_INFORMATION mbi; DWORD written_bytes;
    HANDLE process_handle, file_handle; DWORD_PTR read_bytes;
    uint8_t buf[0x1000]; dump_t d;

    GetSystemInfo(&si);

    file_handle = CreateFileW(filepath, GENERIC_WRITE, 0,
        NULL, CREATE_ALWAYS, 0, NULL);
    if(file_handle == NULL) {
        error("[-] Error opening dump filepath: %S\n", filepath);
    }

    process_handle = open_process(pid);

    uint8_t *ptr = si.lpMinimumApplicationAddress;

    while (ptr < (uint8_t *) si.lpMaximumApplicationAddress) {
        if(VirtualQueryEx(process_handle, ptr, &mbi, sizeof(mbi)) == FALSE) {
            ptr += 0x1000;
            continue;
        }

        if((mbi.State & MEM_COMMIT) == 0 || (mbi.Protect & PAGE_GUARD) != 0 ||
                (mbi.Type & (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE)) == 0) {
            ptr += mbi.RegionSize;
            continue;
        }

        d.addr = (uintptr_t) ptr;
        d.size = mbi.RegionSize;
        d.state = mbi.State;
        d.type = mbi.Type;
        d.protect = mbi.Protect;

        // If --dump-block is specified, restrict to a particular block.
        if(addr != 0 && length != 0 && (
                d.addr < addr || d.addr > addr + length)) {
            ptr += 0x1000;
            continue;
        }

        WriteFile(file_handle, &d, sizeof(d), &written_bytes, NULL);

        for (uint8_t *end = ptr + mbi.RegionSize; ptr < end; ptr += 0x1000) {
            if(ReadProcessMemory(process_handle, ptr, buf, sizeof(buf),
                    &read_bytes) == FALSE || read_bytes != sizeof(buf)) {
                error("[-] Unable to read a full page?!");
            }

            WriteFile(file_handle, buf, sizeof(buf), &written_bytes, NULL);
        }
    }

    CloseHandle(process_handle);
    CloseHandle(file_handle);
    return 0;
}

int main()
{
    LPWSTR *argv; int argc;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if(argv == NULL) {
        error("Error parsing commandline options!\n");
    }

    if(argc < 4) {
        error(
            "Usage: %S <options..>\n"
            "Options:\n"
            "  --crt                  CreateRemoteThread injection\n"
            "  --apc                  QueueUserAPC injection\n"
            "  --free                 Do not inject our monitor\n"
            "  --dll <dll>            DLL to inject\n"
            "  --app <app>            Path to application to start\n"
            "  --args <args>          Command-line arguments\n"
            "                         Excluding the application path!\n"
            "  --curdir <dirpath>     Current working directory\n"
            "  --maximize             Maximize the newly created GUI\n"
            "  --pid <pid>            Process identifier to inject\n"
            "  --process-name <name>  Process name to inject\n"
            "  --tid <tid>            Thread identifier to inject\n"
            "  --from <pid>           Inject from another process\n"
            "  --from-process <name>  "
            "Inject from another process, resolves pid\n"
            "  --only-start           "
            "Start the application and print pid/tid\n"
            "  --resume-thread        "
            "Resume the thread of the pid/tid target\n"
            "  --config <path>        "
            "Configuration file for the monitor\n"
            "  --dbg <path>           "
            "Attach debugger to target process\n"
            "  --dump <filepath>      "
            "Dump process memory with --pid to filepath\n"
            "  --dump-block <addr> <length> "
            "Restrict process memory dump to a particular block\n"
            "  --verbose              Verbose switch\n",
            argv[0]
        );
    }

    const wchar_t *dll_path = NULL, *app_path = NULL, *arguments = L"";
    const wchar_t *config_file = NULL, *from_process = NULL, *dbg_path = NULL;
    const wchar_t *curdir = NULL, *process_name = NULL, *dump_path = NULL;
    uint32_t pid = 0, tid = 0, from = 0, inj_mode = INJECT_NONE, partial = 0;
    uint32_t show_window = SW_SHOWNORMAL, only_start = 0, resume_thread_ = 0;
    uintptr_t dump_addr = 0, dump_length = 0;

    for (int idx = 1; idx < argc; idx++) {
        if(wcscmp(argv[idx], L"--crt") == 0) {
            inj_mode = INJECT_CRT;
            continue;
        }

        if(wcscmp(argv[idx], L"--apc") == 0) {
            inj_mode = INJECT_APC;
            continue;
        }

        if(wcscmp(argv[idx], L"--free") == 0) {
            inj_mode = INJECT_FREE;
            continue;
        }

        if(wcscmp(argv[idx], L"--dll") == 0) {
            dll_path = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--app") == 0) {
            app_path = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--args") == 0) {
            arguments = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--curdir") == 0) {
            curdir = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--maximize") == 0) {
            show_window = SW_MAXIMIZE;
            continue;
        }

        if(wcscmp(argv[idx], L"--pid") == 0) {
            pid = wcstol(argv[++idx], NULL, 10);
            continue;
        }

        if(wcscmp(argv[idx], L"--process-name") == 0) {
            process_name = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--tid") == 0) {
            tid = wcstol(argv[++idx], NULL, 10);
            continue;
        }

        if(wcscmp(argv[idx], L"--from") == 0) {
            from = wcstol(argv[++idx], NULL, 10);
            continue;
        }

        if(wcscmp(argv[idx], L"--from-process") == 0) {
            from_process = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--only-start") == 0) {
            partial = only_start = 1;
            continue;
        }

        if(wcscmp(argv[idx], L"--resume-thread") == 0) {
            partial = resume_thread_ = 1;
            continue;
        }

        if(wcscmp(argv[idx], L"--config") == 0) {
            config_file = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--dbg") == 0) {
            dbg_path = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--dump") == 0) {
            dump_path = argv[++idx];
            continue;
        }

        if(wcscmp(argv[idx], L"--dump-block") == 0) {
            dump_addr = wcstoull(argv[++idx], NULL, 16);
            dump_length = wcstoull(argv[++idx], NULL, 10);
            continue;
        }

        if(wcscmp(argv[idx], L"--verbose") == 0) {
            verbose = 1;
            continue;
        }

        error("[-] Found unsupported argument: %S\n", argv[idx]);
        return 1;
    }

    // Dump memory of a process.
    if(dump_path != NULL && pid != 0) {
        dump(pid, dump_path, dump_addr, dump_length);
        return 0;
    }

    if(inj_mode == INJECT_NONE && partial == 0) {
        error("[-] No injection method has been provided!\n");
    }

    if(inj_mode == INJECT_CRT && pid == 0 && process_name == NULL &&
            app_path == NULL) {
        error("[-] No injection target has been provided!\n");
    }

    if(inj_mode == INJECT_APC && tid == 0 && process_name == NULL &&
            app_path == NULL) {
        error("[-] No injection target has been provided!\n");
    }

    if(inj_mode == INJECT_FREE && app_path == NULL && pid == 0) {
        error("[-] An app path is required when not injecting!\n");
    }

    if(pid != 0 && process_name != NULL) {
        error("[-] Both pid and process-name were set!\n");
    }

    static wchar_t dllpath[MAX_PATH_W];

    if(inj_mode == INJECT_FREE && partial == 0) {
        if(dll_path != NULL || tid != 0 || pid != 0) {
            error("[-] Unused --tid/--pid/--dll provided in --free mode!\n");
        }
    }

    if(inj_mode != INJECT_NONE && inj_mode != INJECT_FREE) {
        if(PathFileExistsW(dll_path) == FALSE) {
            error("[-] Invalid DLL filepath has been provided\n");
        }

        if(GetFullPathNameW(dll_path, MAX_PATH_W, dllpath, NULL) == 0) {
            error("[-] Invalid DLL filepath has been provided\n");
        }

        if(GetLongPathNameW(dllpath, dllpath, MAX_PATH_W) == 0) {
            error("[-] Error obtaining the dll long path name\n");
        }
    }

    if(from != 0 && from_process != NULL) {
        error("[-] Both --from and --from-process are specified\n");
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
            from = GetCurrentProcessId();
        }

        if(PathFileExistsW(app_path) == FALSE) {
            error("[-] Invalid app filepath has been provided\n");
        }

        static wchar_t dirpath[MAX_PATH_W], filepath[MAX_PATH_W];

        // If a current working directory has been set then we use that
        // current working directory. Otherwise default to $TEMP.
        if(curdir != NULL) {
            // Allow the current working directory to be
            // specified as, e.g., %TEMP%.
            if(ExpandEnvironmentStringsW(curdir, dirpath, MAX_PATH_W) == 0) {
                error("[-] Error expanding environment variables\n");
            }

            curdir = dirpath;
        }
        else {
            // We don't want to be expanding the environment variable buffer
            // as that will probably corrupt the heap or so.
            curdir = wcscpy(dirpath, _wgetenv(L"TEMP"));
        }

        if(GetLongPathNameW(dirpath, dirpath, MAX_PATH_W) == 0) {
            error("[-] Error obtaining the curdir long path name\n");
        }

        if(GetFullPathNameW(app_path, MAX_PATH_W, filepath, NULL) == 0) {
            error("[-] Invalid app filepath has been provided\n");
        }

        if(GetLongPathNameW(filepath, filepath, MAX_PATH_W) == 0) {
            error("[-] Error obtaining the app long path name\n");
        }

        pid = start_app(from, filepath, arguments, curdir, &tid, show_window);
    }

    if(pid == 0 && process_name != NULL) {
        pid = pid_from_process_name(process_name);
    }

    // Drop the configuration file if available.
    if(config_file != NULL) {
        static wchar_t filepath[MAX_PATH_W];

        wsprintfW(filepath, L"C:\\cuckoo_%d.ini", pid);
        if(MoveFileW(config_file, filepath) == FALSE) {
            error("[-] Error dropping configuration file: %ld\n",
                GetLastError());
        }
    }

    // Do not do actual injection here, just have the application launched.
    if(only_start != 0) {
        printf("%d %d", pid, tid);
        return 0;
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
        error("[-] Unhandled injection mode: %d\n", inj_mode);
    }

    if(dbg_path != NULL) {
        wchar_t buf[1024];
        wsprintfW(buf, L"\"%s\" -p %d", dbg_path, pid);

        start_app(GetCurrentProcessId(), dbg_path, buf,
            NULL, NULL, SW_SHOWNORMAL);

        Sleep(5000);
    }

    if((app_path != NULL || resume_thread_ != 0) && tid != 0) {
        resume_thread(tid);
    }

    // Report the process and thread identifiers.
    printf("%d %d", pid, tid);
    return 0;
}
