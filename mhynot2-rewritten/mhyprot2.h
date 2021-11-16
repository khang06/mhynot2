#pragma once

#include <cstdint>

// https://github.com/kagurazakasanae/Mhyprot2DrvControl/blob/main/Driver/MhyProt2.cs
enum class MhyProt2Ioctl : unsigned {
    DrvInit = 0x80034000,
    MDL = 0x81004000,
    HeartBeat = 0x81014000,
    HeartBeat2 = 0x80024000, // 1.5-dev calls this "ProcessHips"?
    RWMemory = 0x81074000,
    EnumProcessList = 0x83014000,
    ListProcessModule = 0x81054000,
    FreeSharedMemory = 0x82004000,
    EnumDrivers = 0x82024000,
    KillProcess = 0x81034000,
    GetDriverStatus = 0x82114000,
    GetDriverVersion = 0x81084000,
    GetProcessHandles = 0x82034000 // only seems to get "Process" and "DebugHandle" handles
};

struct ListProcessModuleRequest {
    uint32_t pid;
    uint32_t max_count;
};
static_assert(sizeof(ListProcessModuleRequest) == 8, "ListProcessModuleRequest is the wrong size!!!");
struct ListProcessModuleResponse {
    void* base;
    uint32_t size;
    wchar_t name[128];
    wchar_t path[MAX_PATH];
    //uint32_t pad; // probably handled by the compiler anyways
};
static_assert(sizeof(ListProcessModuleResponse) == 0x318, "ListProcessModuleResponse is the wrong size!!!");

struct EnumProcessListRequest {
    uint32_t struct_size; // should always be 0x88?
    uint32_t max_count;
    char pad[0x88 - 0x8];
};
static_assert(sizeof(EnumProcessListRequest) == 0x88, "EnumProcessListRequest is the wrong size!!!");
struct EnumProcessListResponse {
    int pid;
    wchar_t path[MAX_PATH];
    void* eprocess; // yes, this is a kernel-mode address...
    uint64_t create_time;
    int is_64bit;
    char gap224[0x84]; // never seems to get filled in anywhere
};
static_assert(sizeof(EnumProcessListResponse) == 0x2A8, "EnumProcessListResponse is the wrong size!!!");

struct RWMemoryRequest {
    uint64_t mode; // 1 to copy memory from current process to target, 0 for the other way around
    uint32_t target_pid;
    //uint32_t pad; // probably handled by the compiler anyways
    void* to_addr;
    void* from_addr;
    uint32_t size;
};
static_assert(sizeof(RWMemoryRequest) == 0x28, "RWMemoryRequest is the wrong size!!!");
// just returns a u32 for response as a return code

struct MDLRequest {
    HANDLE process_event;
    HANDLE image_event;
    HANDLE thread_event;
    HANDLE heartbeat_event;
};
static_assert(sizeof(MDLRequest) == 0x20, "MDLRequest is the wrong size!!!");
struct MDLResponse {
    void* process_shared_mem;
    void* image_shared_mem;
    void* thread_shared_mem;
    void* dummy; // always 0
};
static_assert(sizeof(MDLResponse) == 0x20, "MDLResponse is the wrong size!!!");

struct GetProcessHandlesRequest {
    uint32_t unknown;
    uint32_t pid;
};
static_assert(sizeof(GetProcessHandlesRequest) == 0x8, "GetProcessHandlesRequest is the wrong size!!!");
struct GetProcessHandlesEntry {
    char gap0[4];
    int handle;
    void* obj_body;
    wchar_t path[259];
    char gap216[6];
    wchar_t type[259];
    //int pad; // probably handled by the compiler
};
static_assert(sizeof(GetProcessHandlesEntry) == 0x428, "GetProcessHandlesEntry is the wrong size!!!");
struct GetProcessHandlesResponse {
    uint32_t status;
    uint32_t count;
    GetProcessHandlesEntry* shared_mem;
    void* pmdl;       // kernel address
    void* kernel_mem; // kernel address
};
static_assert(sizeof(GetProcessHandlesResponse) == 0x20, "GetProcessHandlesResponse is the wrong size!!!");

struct EnumDriversRequest {
    uint32_t unk1;
    uint32_t unk2;
};
static_assert(sizeof(EnumDriversRequest) == 0x8, "EnumDriversRequest is the wrong size!!!");
struct EnumDriversEntry {
    char gap0[8];
    void* base;
    uint32_t size;
    char gap14[256];
    wchar_t path[259];
    char gap31A[262];
};
static_assert(sizeof(EnumDriversEntry) == 0x420, "EnumDriversEntry is the wrong size!!!");
struct EnumDriversResponse {
    uint32_t status;
    uint32_t count;
    EnumDriversEntry* shared_mem;
    void* pmdl;       // kernel address
    void* kernel_mem; // kernel address
};
static_assert(sizeof(EnumDriversResponse) == 0x20, "EnumDriversResponse is the wrong size!!!");

struct FreeSharedMemoryRequest {
    void* shared_mem;
    void* pmdl;       // kernel address
    void* kernel_mem; // kernel address
};
static_assert(sizeof(FreeSharedMemoryRequest) == 0x18, "FreeSharedMemoryRequest is the wrong size!!!");
// response is only a uint32_t

// could be done with macros or something
static const char* IoctlToString(unsigned ioctl) {
    switch (ioctl) {
    case (unsigned)MhyProt2Ioctl::DrvInit:
        return "DrvInit";
    case (unsigned)MhyProt2Ioctl::MDL:
        return "MDL";
    case (unsigned)MhyProt2Ioctl::HeartBeat:
        return "HeartBeat";
    case (unsigned)MhyProt2Ioctl::HeartBeat2:
        return "HeartBeat2";
    case (unsigned)MhyProt2Ioctl::RWMemory:
        return "RWMemory";
    case (unsigned)MhyProt2Ioctl::EnumProcessList:
        return "EnumProcessList";
    case (unsigned)MhyProt2Ioctl::ListProcessModule:
        return "ListProcessModule";
    case (unsigned)MhyProt2Ioctl::FreeSharedMemory:
        return "FreeSharedMemory";
    case (unsigned)MhyProt2Ioctl::EnumDrivers:
        return "EnumDrivers";
    case (unsigned)MhyProt2Ioctl::KillProcess:
        return "KillProcess";
    case (unsigned)MhyProt2Ioctl::GetDriverStatus:
        return "GetDriverStatus";
    case (unsigned)MhyProt2Ioctl::GetDriverVersion:
        return "GetDriverVersion";
    case (unsigned)MhyProt2Ioctl::GetProcessHandles:
        return "GetProcessHandles";
    default:
        return "???";
    }
}