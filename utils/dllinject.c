#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[])
{
    if(argc < 4) {
        printf("Usage: %s <dll> [dbg] -- <app> [args..]\n", argv[0]);
        return 1;
    }

    const char *dll_path = NULL, *app_path = NULL, *dbg_path = NULL;
    char **args = NULL;

    int at_opt = 0;
    for (int idx = 1; idx < argc; idx++) {
        if(strcmp(argv[idx], "--") == 0) {
            at_opt = 1;
            continue;
        }

        if(dll_path == NULL && at_opt == 0) {
            dll_path = argv[idx];
            continue;
        }

        if(dbg_path == NULL && at_opt == 0) {
            dbg_path = argv[idx];
            continue;
        }

        app_path = argv[idx];
        args = &argv[idx];
        break;
    }

    if(app_path == NULL) {
        printf("[-] The application path has not been set!\n");
        return 1;
    }

    FARPROC load_library_a =
        GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
    if(load_library_a == NULL) {
        fprintf(stderr, "Error resolving LoadLibraryA?!\n");
        return 1;
    }

    OFSTRUCT of; memset(&of, 0, sizeof(of)); of.cBytes = sizeof(of);
    if(OpenFile(dll_path, &of, OF_EXIST) == HFILE_ERROR) {
        fprintf(stderr, "DLL file does not exist!\n");
        return 1;
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    char fname[MAX_PATH];
    sprintf(fname, "%ld-out.txt", GetCurrentProcessId());

    printf("[x] Log files at %ld-{out,err}.txt!\n", GetCurrentProcessId());

    HANDLE out_file = CreateFile(fname, GENERIC_WRITE, 0, &sa,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(out_file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Unable to create stdout file: %ld (%s)!\n",
            GetLastError(), fname);
        return 1;
    }

    sprintf(fname, "%ld-err.txt", GetCurrentProcessId());
    HANDLE err_file = CreateFile(fname, GENERIC_WRITE, 0, &sa,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(err_file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Unable to create stderr file: %ld (%s)!\n",
            GetLastError(), fname);
        return 1;
    }

    STARTUPINFO si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out_file;
    si.hStdError = err_file;

    printf("[x] DLL: '%s'\n", dll_path);
    printf("[x] App: '%s'\n", app_path);

    char cmdline[512], *ptr;

    ptr = cmdline;
    for (int idx = 0; args[idx] != NULL; idx++) {
        // Only apply quotation marks if a cmdline argument has at least one
        // space or quotation mark.
        int quotate = 0;
        for (const char *p = args[idx]; *p != 0; p++) {
            if(*p == ' ' || *p == '"') {
                quotate = 1;
                break;
            }
        }

        if(quotate != 0) {
            *ptr++ = '"';
        }

        printf("[x] Arg[%d]: '%s'\n", idx, args[idx]);

        for (const char *p = args[idx]; *p != 0; p++) {
            if(*p == '"') {
                *ptr++ = '\\';
            }

            *ptr++ = *p;
        }

        if(quotate != 0) {
            *ptr++ = '"';
        }

        *ptr++ = ' ';
    }
    *ptr = 0;

    if(CreateProcessA(app_path, cmdline, NULL, NULL, TRUE, CREATE_SUSPENDED,
            NULL, NULL, &si, &pi) == FALSE) {
        fprintf(stderr, "Error launching process: %ld!\n", GetLastError());
        return 1;
    }

    void *lib = VirtualAllocEx(pi.hProcess, NULL, strlen(dll_path) + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(lib == NULL) {
        fprintf(stderr, "Error allocating memory in the process: %ld!\n",
            GetLastError());
        goto error;
    }

    unsigned long bytes_written;
    if(WriteProcessMemory(pi.hProcess, lib, dll_path, strlen(dll_path) + 1,
            &bytes_written) == FALSE ||
            bytes_written != strlen(dll_path) + 1) {
        fprintf(stderr, "Error writing lib to the process: %ld\n",
            GetLastError());
        goto error;
    }

    if(QueueUserAPC((PAPCFUNC) load_library_a, pi.hThread,
            (ULONG_PTR) lib) == 0) {
        fprintf(stderr, "Error queueing APC to the process: %ld\n",
            GetLastError());
        goto error;
    }

    printf("[x] Injected successfully!\n");

    if(dbg_path != NULL) {
        sprintf(fname, "\"%s\" -p %ld", dbg_path, pi.dwProcessId);

        STARTUPINFO si2; PROCESS_INFORMATION pi2;
        memset(&si2, 0, sizeof(si2)); si2.cb = sizeof(si2);
        CreateProcess(dbg_path, fname, NULL, NULL, FALSE, 0,
            NULL, NULL, &si2, &pi2);

        CloseHandle(pi2.hThread);
        CloseHandle(pi2.hProcess);

        Sleep(5000);
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;

error:
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}
