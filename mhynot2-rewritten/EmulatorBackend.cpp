#include <cassert>
#include <Windows.h>
#include <psapi.h>
#include <shlwapi.h>

#include "PacketCrypt.h"
#include "EmulatorBackend.h"
#include "mhyprot2.h"

bool heartbeat_thread_started = false;
DWORD WINAPI HeartbeatThread(LPVOID lpParameter) {
    printf("Hello from HeartbeatThread!\n");
    uint64_t iters = 0;
    while (true) {
        Sleep(100);
        iters++;
        if (iters % 30 == 11) {
            // technically this should be KeSetEvent(heartbeat_event, 0, 0)
            // hopefully those are the same thing
            SetEvent(lpParameter);
        }
    }
    return 0;
}

std::optional<SC_HANDLE> EmulatorBackend::CreateServiceWHook(LPCWSTR lpServiceName) {
    if (!wcsncmp(lpServiceName, L"mhyprot2", 256)) {
        service_created = true;
        return DUMMY_HANDLE;
    }
    return (SC_HANDLE)NULL;
}
std::optional<SC_HANDLE> EmulatorBackend::OpenServiceWHook(LPCWSTR lpServiceName) {
    if (service_created && !wcsncmp(lpServiceName, L"mhyprot2", 256))
        return DUMMY_HANDLE;
    return (SC_HANDLE)NULL;
}
std::optional<BOOL> EmulatorBackend::StartServiceWHook(SC_HANDLE hService) {
    if (hService == DUMMY_HANDLE)
        return TRUE;
    return FALSE;
}
std::optional<BOOL> EmulatorBackend::ControlServiceHook(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus) {
    assert(dwControl == 1);
    assert(hService == DUMMY_HANDLE);

    lpServiceStatus->dwServiceType = SERVICE_KERNEL_DRIVER;
    lpServiceStatus->dwCurrentState = SERVICE_STOP_PENDING; // not sure why it's like this
    lpServiceStatus->dwControlsAccepted = SERVICE_ACCEPT_STOP;
    lpServiceStatus->dwWin32ExitCode = NO_ERROR;
    lpServiceStatus->dwServiceSpecificExitCode = NO_ERROR;
    lpServiceStatus->dwCheckPoint = 0;
    lpServiceStatus->dwWaitHint = 0;

    return TRUE;
}
std::optional<BOOL> EmulatorBackend::DeleteServiceHook(SC_HANDLE hService) {
    assert(hService == DUMMY_HANDLE);
    service_created = false;
    return TRUE;
}
std::optional<BOOL> EmulatorBackend::CloseServiceHandleHook(SC_HANDLE hService) {
    if (hService == DUMMY_HANDLE)
        return TRUE;
    return {};
}

std::optional<HANDLE> EmulatorBackend::OpenDriverPipe() {
    return DUMMY_HANDLE;
}
std::optional<std::vector<uint8_t>> EmulatorBackend::DriverInit(LPVOID input) {
    auto val = PacketCrypt::Init(((uint64_t*)input)[1] ^ 0xEBBAAEF4FFF89042);

    std::vector<uint8_t> ret;
    ret.resize(8);
    memcpy(ret.data(), &val, sizeof(val));
    return ret;
}
std::optional<std::vector<uint8_t>> EmulatorBackend::HandleIOCTLRequest(DWORD control_code, std::vector<uint8_t> input) {
    // TODO: temporary until everything is emulated
    std::optional<std::vector<uint8_t>> output = {};

    // TODO: messy, needs to be refactored...
    switch (control_code) {
    case (DWORD)MhyProt2Ioctl::HeartBeat: {
        auto out = std::vector<uint8_t>();
        out.resize(8);
        *(uint64_t*)out.data() = 0xc8;
        output = out;
        break;
    }
    case (DWORD)MhyProt2Ioctl::HeartBeat2: {
        auto out = std::vector<uint8_t>();
        out.resize(8);
        *(uint64_t*)out.data() = 2;
        output = out;
        break;
    }
    case (DWORD)MhyProt2Ioctl::GetDriverStatus:
    case (DWORD)MhyProt2Ioctl::GetDriverVersion: {
        auto out = std::vector<uint8_t>();
        out.resize(4);
        *(uint32_t*)out.data() = 0;
        output = out;
        break;
    }
    case (DWORD)MhyProt2Ioctl::ListProcessModule: {
        assert(input.size() == sizeof(ListProcessModuleRequest));
        auto* req = (ListProcessModuleRequest*)input.data();
        printf("pid: 0x%x (%ls), max count: %d\n", req->pid, Common::PIDToProcessName(req->pid).c_str(), req->max_count);

        std::vector<ListProcessModuleResponse> modules;

        assert(req->pid == GetCurrentProcessId());
        
        HMODULE hmodules[512];
        DWORD hmodules_size;
        // even if the requested size is too small, this loop still needs to happen in order to give an accurate count
        if (EnumProcessModules(GetCurrentProcess(), hmodules, sizeof(hmodules), &hmodules_size)) {
            for (int i = 0; i < (hmodules_size / sizeof(HMODULE)); i++) {
                auto mod = hmodules[i];
                MODULEINFO mod_info = {};
                GetModuleInformation(GetCurrentProcess(), mod, &mod_info, sizeof(mod_info));

                ListProcessModuleResponse res = {};

                res.base = mod; // HMODULEs are just pointers to the base
                GetModuleFileNameW(mod, res.path, MAX_PATH);
                wcsncpy(res.name, PathFindFileNameW(res.path), sizeof(res.name) / sizeof(wchar_t));
                res.size = mod_info.SizeOfImage;

                // TODO: make this configurable!
                const std::wstring blacklisted_modules[] = {
                    L"HookLibraryx64.dll",    // ScyllaHide
                    L"mhynot2-rewritten.dll", // hmmmmmmmm
                };
                // TODO: case sensitive!
                bool is_blacklisted = false;
                for (auto name : blacklisted_modules) {
                    if (name == res.name) {
                        printf(YEL "Blocked enumeration of blacklisted module %ls\n" WHT, res.name);
                        is_blacklisted = true;
                        break;
                    }
                }
                if (!is_blacklisted)
                    modules.push_back(res);
            }
        } else {
            Common::Panic("EnumProcessModules failed!");
        }

        // TODO: this is messy and probably should be abstracted out
        auto out = std::vector<uint8_t>();
        out.resize(modules.size() * sizeof(ListProcessModuleResponse) + 4);
        *(uint32_t*)out.data() = (uint32_t)modules.size();
        if (modules.size() <= req->max_count)
            memcpy(out.data() + 4, modules.data(), modules.size() * sizeof(ListProcessModuleResponse));
        output = out;

        break;
    }
    case (DWORD)MhyProt2Ioctl::EnumProcessList: {
        assert(input.size() == sizeof(EnumProcessListRequest));
        auto* req = (EnumProcessListRequest*)input.data();
        printf("struct size: 0x%x, max count: %d\n", req->struct_size, req->max_count);

        // TODO: should have some fake processes, just listing own process for now
        EnumProcessListResponse res = {};
        
        // TODO: do i really need all of these fields?
        FILETIME creation_time;
        FILETIME exit_time;
        FILETIME kernel_time;
        FILETIME user_time;
        if (!GetProcessTimes(GetCurrentProcess(), &creation_time, &exit_time, &kernel_time, &user_time))
            Common::Panic("GetProcessTimes failed! GLE: 0x%x", GetLastError());

        memcpy(&res.create_time, &creation_time, sizeof(res.create_time));
        res.eprocess = (void*)0xFFFF8002B86962E0; // just some random kernel pointer
        res.pid = GetCurrentProcessId();
        res.is_64bit = true;
        GetModuleFileNameW(NULL, res.path, MAX_PATH);

        auto out = std::vector<uint8_t>();
        out.resize(sizeof(res) + 4);
        *(uint32_t*)out.data() = 1;
        memcpy(out.data() + 4, &res, sizeof(res));
        output = out;
        break;
    }
    case (DWORD)MhyProt2Ioctl::RWMemory: {
        assert(input.size() == sizeof(RWMemoryRequest));
        auto* req = (RWMemoryRequest*)input.data();
        printf("mode: %s, pid: 0x%x (%ls), to_addr: %p, from_addr: %p, size: 0x%d\n",
            req->mode ? "this -> target" : "target -> this", req->target_pid, Common::PIDToProcessName(req->target_pid).c_str(), req->to_addr, req->from_addr, req->size);

        assert(req->target_pid == GetCurrentProcessId());

        // probably should virtualprotect if necessary, but it seems fine for now
        memcpy(req->to_addr, req->from_addr, req->size);

        // TODO: technically still getting detected anyways
        if (req->from_addr == &__ImageBase) {
            printf(RED "Shitty evasive measure running!\n" WHT);
            memset(req->to_addr, 0, req->size);
        }

        auto out = std::vector<uint8_t>();
        out.resize(4);
        *(uint32_t*)out.data() = 0;
        output = out;
        break;
    }
    case (DWORD)MhyProt2Ioctl::MDL: {
        assert(input.size() == sizeof(MDLRequest));
        auto* req = (MDLRequest*)input.data();
        printf("process_event: %p, image_event: %p, thread_event: %p, heartbeat_event: %p\n",
            req->process_event, req->image_event, req->thread_event, req->heartbeat_event);

        // other events not handled, just heartbeat
        assert(!heartbeat_thread_started);
        heartbeat_thread_started = true;

        CreateThread(NULL, 0, HeartbeatThread, req->heartbeat_event, 0, NULL);

        // since those threads are never signalled, hopefully the client never accesses these
        // if it does, it should be easy to tell which one it tried accessing
        MDLResponse res;
        res.image_shared_mem = (void*)0xCAFEBEBECAFEBEBE;
        res.process_shared_mem = (void*)0xCAFEB0BACAFEB0BA;
        res.thread_shared_mem = (void*)0xCAFED00DCAFED00D;
        res.dummy = nullptr;

        auto out = std::vector<uint8_t>();
        out.resize(sizeof(res));
        memcpy(out.data(), &res, sizeof(res));
        output = out;
        break;
    }
    case (DWORD)MhyProt2Ioctl::FreeSharedMemory: {
        assert(input.size() == sizeof(FreeSharedMemoryRequest));
        auto* req = (FreeSharedMemoryRequest*)input.data();
        printf("shared_mem: %p, pmdl: %p, kernel_mem: %p\n", req->shared_mem, req->pmdl, req->kernel_mem);

        // ignore the kernel addresses
        assert(req->shared_mem != nullptr);
        free(req->shared_mem);

        auto out = std::vector<uint8_t>();
        out.resize(4);
        *(uint32_t*)out.data() = 0;
        output = out;
        break;
    }
    case (DWORD)MhyProt2Ioctl::GetProcessHandles: {
        assert(input.size() == sizeof(GetProcessHandlesRequest));
        auto* req = (GetProcessHandlesRequest*)input.data();
        printf("pid: 0x%xp (%ls)\n", req->pid, Common::PIDToProcessName(req->pid).c_str());

        // just pretend like there are no handles that match what it wants
        GetProcessHandlesResponse res = {};
        res.status = 0xFFFFFFFF;

        auto out = std::vector<uint8_t>();
        out.resize(sizeof(res));
        memcpy(out.data(), &res, sizeof(res));
        output = out;
        break;
    }
    case (DWORD)MhyProt2Ioctl::EnumDrivers: {
        assert(input.size() == sizeof(EnumDriversRequest));
        auto* req = (EnumDriversRequest*)input.data();
        printf("unk1: 0x%x, unk2 0x%x\n", req->unk1, req->unk2);

        assert(req->unk1 == 0 && req->unk2 == 0);

        std::vector<EnumDriversEntry> driver_vec;
        LPVOID drivers[512];
        DWORD drivers_size;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &drivers_size)) {
            for (int i = 0; i < (drivers_size / sizeof(LPVOID)); i++) {
                auto drv = drivers[i];
               
                // no driver blacklist but i don't think most people would need that
                EnumDriversEntry res = {};
                res.base = drv;
                GetDeviceDriverFileNameW(drv, res.path, sizeof(res.path) / sizeof(wchar_t));
                res.size = 0x420000; // there doesn't appear to be a way to get the driver size from usermode

                driver_vec.push_back(res);
            }
        }
        else {
            Common::Panic("EnumDeviceDrivers failed!");
        }

        // more bogus kernel addresses
        // it's important that FreeSharedMemory is handled too, or else a BSoD might happen
        EnumDriversResponse res = {};
        res.status = 0;
        res.count = driver_vec.size();
        res.kernel_mem = (void*)0xDEAD2BADDEAD2BAD;
        res.pmdl = (void*)0xDEADD00DDEADD00D;
        res.shared_mem = (EnumDriversEntry*)malloc(driver_vec.size() * sizeof(EnumDriversEntry));
        if (res.shared_mem == nullptr)
            Common::Panic("HOW");

        memcpy(res.shared_mem, driver_vec.data(), driver_vec.size() * sizeof(EnumDriversEntry));

        auto out = std::vector<uint8_t>();
        out.resize(sizeof(res));
        memcpy(out.data(), &res, sizeof(res));
        output = out;
        break;
    }
    default: {
        printf("Input:\n");
        Common::Hexdump(input.data(), input.size());
    }
    }

    if (output.has_value())
        return PacketCrypt::Encrypt(output.value().data(), output.value().size());

    Common::Panic("unhandled ioctl 0x%x!", control_code);
    return {};
}
void EmulatorBackend::HandleIOCTLResponse(DWORD control_code, std::vector<uint8_t> input, std::vector<uint8_t> output) {
    switch (control_code) {
    case (DWORD)MhyProt2Ioctl::HeartBeat: // ignore, too spammy
    case (DWORD)MhyProt2Ioctl::HeartBeat2:
        break;
    case (DWORD)MhyProt2Ioctl::MDL: {
        assert(output.size() == sizeof(MDLResponse));
        auto* res = (MDLResponse*)output.data();
        printf("process mdl: %p, image mdl: %p, thread mdl: %p\n",
            res->process_shared_mem, res->image_shared_mem, res->thread_shared_mem);
        break;
    }
    case (DWORD)MhyProt2Ioctl::RWMemory:
    case (DWORD)MhyProt2Ioctl::GetDriverStatus:    // always returns 0
    case (DWORD)MhyProt2Ioctl::GetDriverVersion: { // always returns 0
        assert(output.size() == sizeof(uint32_t));
        auto res = *(uint32_t*)output.data();
        printf("status: %d\n", res);
        break;
    }
    case (DWORD)MhyProt2Ioctl::EnumProcessList: {
        auto count = *(uint32_t*)output.data();
        auto req_count = ((EnumProcessListRequest*)input.data())->max_count;
        auto* res = (EnumProcessListResponse*)(output.data() + sizeof(uint32_t));
        printf("process count: %d\n", count);
        if (count <= req_count) {
            int iter_count = min(count, 5);
            printf("first %d processes:\n", iter_count);
            for (int i = 0; i < iter_count; i++) {
                printf("path: %ls, eprocess: %p, is 64-bit: %s\n", res[i].path, res[i].eprocess, res[i].is_64bit ? "yes" : "no");
            }
        } else {
            printf("returned count is more than requested count (%d), ignoring\n", req_count);
        }
        break;
    }
    case (DWORD)MhyProt2Ioctl::ListProcessModule: {
        auto count = *(uint32_t*)output.data();
        auto req_count = ((ListProcessModuleRequest*)input.data())->max_count;
        auto* res = (ListProcessModuleResponse*)(output.data() + sizeof(uint32_t));
        printf("module count: %d\n", count);
        if (count <= req_count) {
            int iter_count = min(count, 5);
            printf("first %d modules:\n", iter_count);
            for (int i = 0; i < iter_count; i++) {
                printf("path: %ls, base: %p, size: 0x%x\n", res[i].path, res[i].base, res[i].size);
            }
        }
        else {
            printf("returned count is more than requested count (%d), ignoring\n", req_count);
        }
        break;
    }
    case (DWORD)MhyProt2Ioctl::GetProcessHandles: {
        assert(output.size() == sizeof(GetProcessHandlesResponse));
        auto* res = (GetProcessHandlesResponse*)output.data();
        printf("status: %d, count: %d\n", res->status, res->count);
        auto* data = res->shared_mem;
        if (data) {
            for (unsigned i = 0; i < res->count; i++)
                printf("handle: 0x%x, type: %ls, obj body: %p\n", data[i].handle, data[i].type, data[i].obj_body);
        }
        break;
    }
    case (DWORD)MhyProt2Ioctl::EnumDrivers: {
        assert(output.size() == sizeof(EnumDriversResponse));
        auto* res = (EnumDriversResponse*)output.data();
        auto* data = res->shared_mem;
        printf("driver count: %d\n", res->count);
        if (data) {
            for (unsigned i = 0; i < res->count; i++)
                printf("path: %ls, size: 0x%x\n", data[i].path, data[i].size);
        }
    }
    /*
    case (DWORD)MhyProt2Ioctl::FreeSharedMemory: {
        // TODO: sometimes this is 32 bytes large?
        assert(output.size() == sizeof(uint32_t));
        auto res = *(uint32_t*)output.data();
        printf("status: %d\n", res);
        break;
    }
    */
    default: {
        printf("Output:\n");
        Common::Hexdump(output.data(), output.size());
    }
    }
}