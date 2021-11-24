#include <Windows.h>
#include <MinHook.h>
#include <mutex>
#include <cassert>
#include <winternl.h>
#include <psapi.h>

#include "Common.h"
#include "mhyprot2.h"
#include "PacketCrypt.h"
#include "EmulatorBackend.h"
#include "PassthroughBackend.h"
#include "Config.h"

#pragma comment(lib, "minhook.x64d.lib")

#pragma region Hooks
// helpers
template <typename T>
inline MH_STATUS MH_CreateHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

// why do i even have to make 3 macros for 1???
#define MAKE_HOOK(x) ret = MH_CreateHookEx(x, MAKE_HOOK_HIDDEN1(x), MAKE_HOOK_HIDDEN2(x)); \
                     if (ret != MH_OK) \
                         Common::Panic("Failed to install "#x" hook (%d)", ret); \
                     ret = MH_EnableHook(x); \
                     if (ret != MH_OK) \
                         Common::Panic("Failed to enable "#x" hook (%d)", ret); \
                     printf("Installed hook for "#x"\n");
#define MAKE_HOOK_HIDDEN1(x) &custom_##x
#define MAKE_HOOK_HIDDEN2(x) &orig_##x

// global data
HANDLE driver_pipe = INVALID_HANDLE_VALUE;
Backend* backend = nullptr;

// hooks
auto orig_DeviceIoControl = (BOOL(WINAPI*)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))nullptr;
std::mutex ioctl_mtx;
BOOL WINAPI custom_DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
    LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) {
    // TODO: should locking be handled by the backend? might improve performance
    const std::lock_guard<std::mutex> lock(ioctl_mtx);

    bool is_driver = hDevice == driver_pipe;
    std::optional<BOOL> hook_ret = {};
    std::optional<std::vector<uint8_t>> custom_output = {};

    if (is_driver) {
        printf(CYN "IOCTL called (tid 0x%x, code 0x%x, %s)\n" WHT, GetCurrentThreadId(), dwIoControlCode, IoctlToString(dwIoControlCode));
        if (dwIoControlCode == (DWORD)MhyProt2Ioctl::DrvInit) {
            assert(nInBufferSize == 0x10);
            custom_output = backend->DriverInit(lpInBuffer);
            if (custom_output.has_value())
                hook_ret = TRUE;
        } else {
            assert(nInBufferSize >= 8);
            auto input = PacketCrypt::Decrypt(lpInBuffer, nInBufferSize);
            custom_output = backend->HandleIOCTLRequest(dwIoControlCode, input);
            if (custom_output.has_value())
                hook_ret = TRUE;
        }
    }

    auto ret = hook_ret.has_value() ? hook_ret.value() : 
        orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);

    if (custom_output.has_value()) {
        // this doesn't handle lpOverlapped but who cares lol
        auto output = custom_output.value();
        auto ret_size = min(output.size(), nOutBufferSize);
        *lpBytesReturned = (DWORD)ret_size;
        memcpy(lpOutBuffer, output.data(), ret_size);
    }

    if (is_driver) {
        if (dwIoControlCode != (DWORD)MhyProt2Ioctl::DrvInit) {
            auto input = PacketCrypt::Decrypt(lpInBuffer, nInBufferSize);
            auto encrypted_output =
                custom_output ? custom_output.value() : std::vector((uint8_t*)lpOutBuffer, (uint8_t*)lpOutBuffer + *lpBytesReturned);
            auto output = PacketCrypt::Decrypt(encrypted_output.data(), encrypted_output.size());
            backend->HandleIOCTLResponse(dwIoControlCode, input, output);
        } else {
            Common::Hexdump(lpOutBuffer, *lpBytesReturned);
        }
    }

    return ret;
}

auto orig_TerminateProcess = (BOOL(WINAPI*)(HANDLE, UINT))nullptr;
BOOL WINAPI custom_TerminateProcess(HANDLE hProcess, UINT uExitCode) {
   //Common::Panic("TerminateProcess called! It's probably trying to kill the debugger!");
    printf("TerminateProcess called! It's probably trying to kill the debugger!\n");
    return FALSE;
}

auto orig_CreateServiceW = (SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD,
    LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR))nullptr;
SC_HANDLE WINAPI custom_CreateServiceW(
    SC_HANDLE hSCManager,
    LPCWSTR   lpServiceName,
    LPCWSTR   lpDisplayName,
    DWORD     dwDesiredAccess,
    DWORD     dwServiceType,
    DWORD     dwStartType,
    DWORD     dwErrorControl,
    LPCWSTR   lpBinaryPathName,
    LPCWSTR   lpLoadOrderGroup,
    LPDWORD   lpdwTagId,
    LPCWSTR   lpDependencies,
    LPCWSTR   lpServiceStartName,
    LPCWSTR   lpPassword) {
    auto hook_ret = backend->CreateServiceWHook(lpServiceName);
    auto ret = hook_ret.has_value() ? hook_ret.value() :
        orig_CreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType,
            dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies,
            lpServiceStartName, lpPassword);
    printf("Creating service %ls (handle %p)\n", lpServiceName, ret);
    return ret;
}

auto orig_OpenServiceW = (SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, DWORD))nullptr;
SC_HANDLE WINAPI custom_OpenServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess) {
    auto hook_ret = backend->OpenServiceWHook(lpServiceName);
    auto ret = hook_ret.has_value() ? hook_ret.value() :
        orig_OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
    printf("OpenServiceW called (service name %ls, ret %p)\n", lpServiceName, ret);
    return ret;
}

auto orig_StartServiceW = (BOOL(WINAPI*)(SC_HANDLE, DWORD, LPCWSTR*))nullptr;
BOOL WINAPI custom_StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors) {
    auto hook_ret = backend->StartServiceWHook(hService);
    auto ret = hook_ret.has_value() ? hook_ret.value() :
        orig_StartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);
    printf("StartServiceW (handle %p) called\n", hService);
    return ret;
}

auto orig_QueryServiceStatus = (BOOL(WINAPI*)(SC_HANDLE, LPSERVICE_STATUS))nullptr;
BOOL WINAPI custom_QueryServiceStatus(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus) {
    auto ret = orig_QueryServiceStatus(hService, lpServiceStatus);
    printf("QueryServiceStatus (handle %p) called\n", hService);
    return ret;
}

auto orig_ControlService = (BOOL(WINAPI*)(SC_HANDLE, DWORD, LPSERVICE_STATUS))nullptr;
BOOL WINAPI custom_ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus) {
    auto hook_ret = backend->ControlServiceHook(hService, dwControl, lpServiceStatus);
    auto ret = hook_ret.has_value() ? hook_ret.value() :
        orig_ControlService(hService, dwControl, lpServiceStatus);
    printf("ControlService (handle %p, dwControl 0x%x) called\n", hService, dwControl);

    printf("dwServiceType: 0x%x\n", lpServiceStatus->dwServiceType);
    printf("dwCurrentState: 0x%x\n", lpServiceStatus->dwCurrentState);
    printf("dwControlsAccepted: 0x%x\n", lpServiceStatus->dwControlsAccepted);
    printf("dwWin32ExitCode: 0x%x\n", lpServiceStatus->dwWin32ExitCode);
    printf("dwServiceSpecificExitCode: 0x%x\n", lpServiceStatus->dwServiceSpecificExitCode);
    printf("dwCheckPoint: 0x%x\n", lpServiceStatus->dwCheckPoint);
    printf("dwWaitHint: 0x%x\n", lpServiceStatus->dwWaitHint);
    return ret;
}

auto orig_DeleteService = (BOOL(WINAPI*)(SC_HANDLE))nullptr;
BOOL WINAPI custom_DeleteService(SC_HANDLE hService) {
    auto hook_ret = backend->DeleteServiceHook(hService);
    auto ret = hook_ret.has_value() ? hook_ret.value() :
        orig_DeleteService(hService);
    printf("DeleteService (handle %p) called\n", hService);
    return ret;
}

auto orig_CloseServiceHandle = (BOOL(WINAPI*)(SC_HANDLE))nullptr;
BOOL WINAPI custom_CloseServiceHandle(SC_HANDLE hService) {
    auto hook_ret = backend->CloseServiceHandleHook(hService);
    auto ret = hook_ret.has_value() ? hook_ret.value() :
        orig_CloseServiceHandle(hService);
    printf("CloseServiceHandle (handle %p) called\n", hService);
    return ret;
}

auto orig_OpenSCManagerW = (SC_HANDLE(WINAPI*)(LPCWSTR, LPCWSTR, DWORD))nullptr;
SC_HANDLE WINAPI custom_OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess) {
    auto hook_ret = backend->OpenSCManagerWHook(lpMachineName, lpDatabaseName, dwDesiredAccess);
    auto ret = hook_ret.has_value() ? hook_ret.value() :
        orig_OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess);
    printf("OpenSCManagerW (lpMachineName %ls, lpDatabaseName %ls, dwDesiredAccess 0x%x) called\n",
        lpMachineName != NULL ? lpMachineName : L"NULL", lpDatabaseName != NULL ? lpDatabaseName : L"NULL", dwDesiredAccess);
    return ret;
}

auto orig_CreateFileW = (HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))nullptr;
HANDLE WINAPI custom_CreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile) {
    bool is_driver = !wcscmp(lpFileName, L"\\\\.\\mhyprot2");
    std::optional<HANDLE> hook_ret = {};
    if (is_driver)
        hook_ret = backend->OpenDriverPipe();

    auto ret = hook_ret.has_value() ? hook_ret.value() :
        orig_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    if (is_driver) {
        printf("Driver pipe opened\n");
        driver_pipe = ret;
    }
    return ret;
}

void InstallHooks() {
    if (MH_Initialize() != MH_OK)
        Common::Panic("Failed to initialize MinHook");

    // needs to be done because just doing normal TerminateProcess points to a thunk in kernel32 (at least on Windows 11)
    auto kernelbase = GetModuleHandle(L"kernelbase.dll");
    if (!kernelbase)
        Common::Panic("Failed to get kernelbase.dll");
    auto TerminateProcess = GetProcAddress(kernelbase, "TerminateProcess");
    if (!TerminateProcess)
        Common::Panic("Failed to find TerminateProcess' address");

    MH_STATUS ret;
    MAKE_HOOK(DeviceIoControl);
    MAKE_HOOK(TerminateProcess);
    MAKE_HOOK(CreateServiceW);
    MAKE_HOOK(OpenServiceW);
    MAKE_HOOK(StartServiceW);
    MAKE_HOOK(QueryServiceStatus);
    MAKE_HOOK(ControlService);
    MAKE_HOOK(DeleteService);
    MAKE_HOOK(CloseServiceHandle);
    MAKE_HOOK(OpenSCManagerW);
    MAKE_HOOK(CreateFileW);
}
#pragma endregion Helpers, hooked functions, etc

// kill the actual mhyprot2 service
void KillService() {
    auto sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (sc == NULL) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            printf("OpenSCManager failed because we aren't running as admin! continuing as usual...\n");
            return;
        }
        Common::Panic("OpenSCManager failed (%d)\n", GetLastError());
    }

    auto service = OpenService(sc, L"mhyprot2", DELETE);
    if (service == NULL) {
        auto gle = GetLastError();
        CloseServiceHandle(sc);
        if (gle == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("mhyprot2 is already deleted, going on as usual...\n");
            return;
        }
        Common::Panic("Couldn't open the mhyprot2 service! (GLE %x)", gle);
    }

    if (!DeleteService(service)) {
        auto gle = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(sc);
        if (gle == ERROR_SERVICE_MARKED_FOR_DELETE) {
            printf("mhyprot2 is already marked for deletion\n");
            return;
        }
        Common::Panic("Got a handle to mhyprot2, but couldn't delete it! (GLE %x)", gle);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(sc);
    printf("Deleted the mhyprot2 service\n");
}

// additional evasive measure since interecepting ListProcessModule isn't enough
// probably the oldest trick in the book for people who actually write this kind of thing on a regular basis
// and i still had to skid it lol!!! https://github.com/StickOfficial/redHook/blob/master/unlinkpeb.h
void UnlinkFromPEB() {
    struct COOLER_PEB_LDR_DATA
    {
        UINT8 _PADDING_[12];
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    };
    struct COOLER_LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        VOID* DllBase;
    };

    auto peb = (PPEB)__readgsqword(0x60);
    auto cooler_ldr = (COOLER_PEB_LDR_DATA*)peb->Ldr;

    auto cur_entry = cooler_ldr->InLoadOrderModuleList.Flink;
    COOLER_LDR_DATA_TABLE_ENTRY* cur = nullptr;

    while (cur_entry != &cooler_ldr->InLoadOrderModuleList && cur_entry != nullptr) {
        cur = CONTAINING_RECORD(cur_entry, COOLER_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (cur->DllBase == &__ImageBase) {
            // no plans on relinking it
            cur->InLoadOrderLinks.Flink->Blink = cur->InLoadOrderLinks.Blink;
            cur->InLoadOrderLinks.Blink->Flink = cur->InLoadOrderLinks.Flink;

            cur->InInitializationOrderLinks.Flink->Blink = cur->InInitializationOrderLinks.Blink;
            cur->InInitializationOrderLinks.Blink->Flink = cur->InInitializationOrderLinks.Flink;

            cur->InMemoryOrderLinks.Flink->Blink = cur->InMemoryOrderLinks.Blink;
            cur->InMemoryOrderLinks.Blink->Flink = cur->InMemoryOrderLinks.Flink;

            printf(GRN "Unlinked from PEB!\n" WHT);

            break;
        }
        cur_entry = cur_entry->Flink;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        // make the console
        if (!AllocConsole())
            Common::Panic("Failed to create a console window");
        freopen("CONOUT$", "w", stdout);

        // get some fancy console colors!
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD consoleMode;
        GetConsoleMode(hConsole, &consoleMode);
        consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hConsole, consoleMode);

        printf(GRN "Mode: %s\n" WHT, Config::EmulatorMode ? "Emulator" : "Passthrough");
        backend = Config::EmulatorMode ? (Backend*)new EmulatorBackend() : (Backend*)new PassthroughBackend();

        KillService();
        InstallHooks();
        UnlinkFromPEB();
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

