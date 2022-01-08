#include <cassert>

#include "PacketCrypt.h"
#include "PassthroughBackend.h"
#include "mhyprot2.h"

std::optional<SC_HANDLE> PassthroughBackend::OpenSCManagerWHook(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess) {
    return {};
}
std::optional<SC_HANDLE> PassthroughBackend::CreateServiceWHook(LPCWSTR lpServiceName) {
	return {};
}
std::optional<SC_HANDLE> PassthroughBackend::OpenServiceWHook(LPCWSTR lpServiceName) {
	return {};
}
std::optional<BOOL> PassthroughBackend::StartServiceWHook(SC_HANDLE hService) {
	return {};
}
std::optional<BOOL> PassthroughBackend::ControlServiceHook(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus) {
	return {};
}
std::optional<BOOL> PassthroughBackend::DeleteServiceHook(SC_HANDLE hService) {
	return {};
}
std::optional<BOOL> PassthroughBackend::CloseServiceHandleHook(SC_HANDLE hService) {
    return {};
}

std::optional<HANDLE> PassthroughBackend::OpenDriverPipe() {
	return {};
}
std::optional<std::vector<uint8_t>> PassthroughBackend::DriverInit(LPVOID input) {
    PacketCrypt::Init(((uint64_t*)input)[1] ^ 0xEBBAAEF4FFF89042);
    return {};
}
std::optional<std::vector<uint8_t>> PassthroughBackend::HandleIOCTLRequest(DWORD control_code, std::vector<uint8_t> input) {
    switch (control_code) {
    case (DWORD)MhyProt2Ioctl::HeartBeat:  // ignore, too spammy
    case (DWORD)MhyProt2Ioctl::HeartBeat2: // ignore, too spammy
    case (DWORD)MhyProt2Ioctl::GetDriverStatus:  // always 0
    case (DWORD)MhyProt2Ioctl::GetDriverVersion: // always 0
        break;
    case (DWORD)MhyProt2Ioctl::ListProcessModule: {
        assert(input.size() == sizeof(ListProcessModuleRequest));
        auto* req = (ListProcessModuleRequest*)input.data();
        printf("pid: 0x%x (%ls), max count: %d\n", req->pid, Common::PIDToProcessName(req->pid).c_str(), req->max_count);
        break;
    }
    case (DWORD)MhyProt2Ioctl::EnumProcessList: {
        assert(input.size() == sizeof(EnumProcessListRequest));
        auto* req = (EnumProcessListRequest*)input.data();
        printf("struct size: 0x%x, max count: %d\n", req->struct_size, req->max_count);
        break;
    }
    case (DWORD)MhyProt2Ioctl::RWMemory: {
        assert(input.size() == sizeof(RWMemoryRequest));
        auto* req = (RWMemoryRequest*)input.data();
        printf("mode: %s, pid: 0x%x (%ls), to_addr: %p, from_addr: %p, size: 0x%x\n",
            req->mode ? "this -> target" : "target -> this", req->target_pid, Common::PIDToProcessName(req->target_pid).c_str(), req->to_addr, req->from_addr, req->size);
        break;
    }
    case (DWORD)MhyProt2Ioctl::MDL: {
        assert(input.size() == sizeof(MDLRequest));
        auto* req = (MDLRequest*)input.data();
        printf("process_event: %p, image_event: %p, thread_event: %p, heartbeat_event: %p\n",
            req->process_event, req->image_event, req->thread_event, req->heartbeat_event);
        break;
    }
    case (DWORD)MhyProt2Ioctl::FreeSharedMemory: {
        assert(input.size() == sizeof(FreeSharedMemoryRequest));
        auto* req = (FreeSharedMemoryRequest*)input.data();
        printf("shared_mem: %p, pmdl: %p, kernel_mem: %p\n", req->shared_mem, req->pmdl, req->kernel_mem);
        break;
    }
    case (DWORD)MhyProt2Ioctl::GetProcessHandles: {
        assert(input.size() == sizeof(GetProcessHandlesRequest));
        auto* req = (GetProcessHandlesRequest*)input.data();
        printf("pid: 0x%xp (%ls)\n", req->pid, Common::PIDToProcessName(req->pid).c_str());
        break;
    }
    case (DWORD)MhyProt2Ioctl::EnumDrivers: {
        assert(input.size() == sizeof(EnumDriversRequest));
        auto* req = (EnumDriversRequest*)input.data();
        printf("unk1: 0x%x, unk2 0x%x\n", req->unk1, req->unk2);
        break;
    }
    default: {
        printf("Input:\n");
        Common::Hexdump(input.data(), input.size());
    }
    }

    return {};
}
void PassthroughBackend::HandleIOCTLResponse(DWORD control_code, std::vector<uint8_t> input, std::vector<uint8_t> output) {
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
            int iter_count = std::min(count, 5u);
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
            int iter_count = std::min(count, 5u);
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
