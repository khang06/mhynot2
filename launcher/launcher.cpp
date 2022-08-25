#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>

int inject_library(HANDLE hProcess, const char* dll) 
{
    auto loadlibrary = LoadLibraryA; // i actually had no idea that the address of kernel32 is the same between all processes
    auto mem = VirtualAllocEx(hProcess, NULL, strlen(dll) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    printf("Injecting library %s\n", dll);
    printf("LoadLibraryA %p\n", loadlibrary);
    printf("allocated path addr %p\n", mem);
    if (!mem) {
        printf("VirtualAllocEx epic fail GLE: 0x%x\n", GetLastError());
        return 1;
    }
    WriteProcessMemory(hProcess, mem, dll, strlen(dll) + 1, NULL);

    auto new_thread = CreateRemoteThread(
        hProcess,
        NULL,
        NULL,
        (LPTHREAD_START_ROUTINE)loadlibrary,
        mem,
        NULL,
        NULL
    );
    if (new_thread == NULL) {
        printf("CreateRemoteThread epic fail GLE: 0x%x\n", GetLastError());
        return 1;
    }

    printf("waiting for the dll loading thread to exit\n");
    WaitForSingleObject(new_thread, INFINITE);

    DWORD ExitCode = 0;
    if (GetExitCodeThread(new_thread, &ExitCode) == 0) {
      printf("Loading thread EPIC FAIL: code %d, GLE 0x%x\n", ExitCode, GetLastError());
    } else {
      printf("looks like the dll injected properly\n");
    }

    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);

    CloseHandle(new_thread);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
      puts("Too few arguments!");
      printf("Usage: %s Genshin_Base_Directory Dll_To_Inject_1 [Dll_To_Inject_2 ...]\n", argv[0]);
      return 1;
    }

    for (int i = 2; i < argc; i++) {
      if (!PathFileExistsA(argv[i])) {
        printf("DLL provided couldn't be found: %s\n");
        return 1;
      }
    }

    if (!SetCurrentDirectoryA(argv[1])) {
      printf("Failed to set working directory, GLE: %d\n", GetLastError());
      return 1;
    }
    SetEnvironmentVariableW(L"__COMPAT_LAYER", L"RunAsInvoker"); // forcefully run as not admin

    STARTUPINFOW startup_info = {};
    startup_info.cb = sizeof(startup_info);
    PROCESS_INFORMATION process_info = {};

    SECURITY_ATTRIBUTES attrib = {};
    attrib.nLength = sizeof(attrib);
    SECURITY_DESCRIPTOR desc = {};

    BOOL created = CreateProcessW(
        L"GenshinImpact.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &startup_info,
        &process_info
    );

    if (created == FALSE) {
        printf("CreateProcessW epic fail GLE 0x%x\n", GetLastError());
        return 1;
    }

    for (int i = 2; i < argc; i++) {
      if (inject_library(process_info.hProcess, argv[i])) {
        printf("Error injecting %s!\n", argv[i]);
        TerminateProcess(process_info.hProcess, 1);
        return 1;
      }
    }

    if (ResumeThread(process_info.hThread) == -1) {
        printf("ResumeThread epic fail GLE: 0x%x\n", GetLastError());
        return 1;
    }

    printf("everything seems to be good, cleaning up!\n");

    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);
    return 0;
}
