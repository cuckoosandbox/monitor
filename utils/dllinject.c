#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[])
{
    if(argc < 3) {
        printf("Usage: %s <dll> <app> [dbg]\n", argv[0]);
        printf("(args currently not supported!)\n");
        return 1;
    }

    FARPROC load_library_a =
        GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
    if(load_library_a == NULL) {
        fprintf(stderr, "Error resolving LoadLibraryA?!\n");
        return 1;
    }

    OFSTRUCT of; memset(&of, 0, sizeof(of)); of.cBytes = sizeof(of);
    if(OpenFile(argv[1], &of, OF_EXIST) == HFILE_ERROR) {
        fprintf(stderr, "Dll file does not exist!\n");
        return 1;
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    char fname[MAX_PATH];
    sprintf(fname, "%ld-out.txt", GetCurrentProcessId());

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

    if(CreateProcessA(argv[2], argv[2], NULL, NULL, TRUE, CREATE_SUSPENDED,
            NULL, NULL, &si, &pi) == FALSE) {
        fprintf(stderr, "Error launching process: %ld!\n", GetLastError());
        return 1;
    }

    void *lib = VirtualAllocEx(pi.hProcess, NULL, strlen(argv[1]) + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(lib == NULL) {
        fprintf(stderr, "Error allocating memory in the process: %ld!\n",
            GetLastError());
        goto error;
    }

    unsigned long bytes_written;
    if(WriteProcessMemory(pi.hProcess, lib, argv[1], strlen(argv[1]) + 1,
            &bytes_written) == FALSE ||
            bytes_written != strlen(argv[1]) + 1) {
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

    if(argc > 3) {
        sprintf(fname, "\"%s\" -p %ld", argv[3], pi.dwProcessId);

        STARTUPINFO si2; PROCESS_INFORMATION pi2;
        memset(&si2, 0, sizeof(si2)); si2.cb = sizeof(si2);
        CreateProcess(argv[3], fname, NULL, NULL, FALSE, 0,
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
